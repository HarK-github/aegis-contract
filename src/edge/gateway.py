"""
FastAPI Ingestion Gateway for AegisContract.
Provides a defensive edge boundary that verifies HMAC signatures,
strictly validates payload bytes against compiled data contracts,
and isolates schema drift into a forensic DLQ with 202 acknowledgment.
"""

import os
import json
import hmac
import hashlib
from pathlib import Path
from typing import Optional, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status, Header, Query
from pydantic import BaseModel

from .contract_loader import compile_contract_from_yaml, CompiledContract
from .dlq_router import QuarantineDLQRouter

# In-memory contract cache and router
CONTRACT_REGISTRY: Dict[str, CompiledContract] = {}
DLQ_ROUTER = QuarantineDLQRouter(dlq_dir="data/dlq")
CLEAN_SINK_FILE = Path("data/clean_events.jsonl")
HMAC_SECRET: Optional[str] = os.getenv("AEGIS_HMAC_SECRET", None)


def load_contracts_from_directory(contracts_dir: str = "contracts"):
    """Recursively loads all YAML contracts into the registry, keyed by ID and version."""
    base_dir = Path(contracts_dir)
    if not base_dir.exists():
        return

    yaml_files = sorted(list(base_dir.rglob("*.yaml")))
    for yaml_path in yaml_files:
        try:
            compiled = compile_contract_from_yaml(str(yaml_path))
            version_key = f"{compiled.contract_id}:{compiled.version}"
            CONTRACT_REGISTRY[version_key] = compiled

            if compiled.version == "1.0.0" or compiled.contract_id not in CONTRACT_REGISTRY:
                CONTRACT_REGISTRY[compiled.contract_id] = compiled

        except Exception as e:
            print(f"Warning: Failed to load contract from {yaml_path}: {e}")


def verify_hmac_signature(body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Verifies HMAC-SHA256 signature against raw request bytes."""
    if not signature_header:
        return False

    provided_hash = signature_header.replace("sha256=", "").strip()
    computed_hash = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_hash, computed_hash)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager replacing deprecated startup/shutdown events."""
    load_contracts_from_directory("contracts")
    CLEAN_SINK_FILE.parent.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="AegisContract Edge Gateway", version="2.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "healthy", "loaded_contracts": list(CONTRACT_REGISTRY.keys())}


@app.get("/contracts")
def list_contracts():
    return {
        key: {
            "version": c.version,
            "target_table": c.warehouse_model.get("target_table"),
            "owner": c.spec.get("owner")
        }
        for key, c in CONTRACT_REGISTRY.items()
    }


@app.post("/ingest/{contract_id}")
async def ingest_event(
    contract_id: str,
    request: Request,
    version: Optional[str] = Query(None),
    x_contract_version: Optional[str] = Header(None),
    x_signature_sha256: Optional[str] = Header(None)
):
    raw_bytes = await request.body()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Verify HMAC if secret is configured
    if HMAC_SECRET:
        if not verify_hmac_signature(raw_bytes, x_signature_sha256, HMAC_SECRET):
            return Response(
                content=json.dumps({"error": "Unauthorized: Invalid or missing HMAC signature"}),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

    # 2. Lookup contract by version if requested, else default
    target_version = version or x_contract_version
    lookup_key = f"{contract_id}:{target_version}" if target_version else contract_id
    contract = CONTRACT_REGISTRY.get(lookup_key) or CONTRACT_REGISTRY.get(contract_id)

    if not contract:
        return Response(
            content=json.dumps({"error": f"Contract '{lookup_key}' not found in registry"}),
            status_code=status.HTTP_404_NOT_FOUND,
            media_type="application/json"
        )

    # 3. Strict Byte Validation
    is_valid, clean_payload, errors = contract.validate_bytes(raw_bytes)

    if is_valid and clean_payload:
        with open(CLEAN_SINK_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(clean_payload, default=str) + "\n")

        return Response(
            content=json.dumps({
                "status": "accepted",
                "contract_id": contract.contract_id,
                "contract_version": contract.version,
                "event_id": clean_payload.get("event_id")
            }, default=str),
            status_code=status.HTTP_200_OK,
            media_type="application/json"
        )
    else:
        dlq_id = DLQ_ROUTER.record_quarantine_event(
            raw_bytes=raw_bytes,
            contract_id=contract.contract_id,
            contract_version=contract.version,
            validation_errors=errors or [],
            client_ip=client_ip
        )

        alert_payload = format_slack_drift_alert(
            contract_id=contract.contract_id,
            contract_version=contract.version,
            dlq_id=dlq_id,
            errors=errors or [],
            client_ip=client_ip
        )

        return Response(
            content=json.dumps({
                "status": "quarantined",
                "contract_id": contract.contract_id,
                "contract_version": contract.version,
                "dlq_id": dlq_id,
                "errors": errors
            }, default=str),
            status_code=status.HTTP_202_ACCEPTED,
            media_type="application/json"
        )
