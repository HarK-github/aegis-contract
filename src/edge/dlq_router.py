"""
Forensic Quarantine Dead-Letter Queue (DLQ) Router for AegisContract.
Captures schema-drifted and invalid payloads with comprehensive forensic metadata,
salted HMAC-SHA256 payload integrity hashing, automated deep PII masking for operator logs,
and a segregated base64 raw payload for uncompromised machine replay.
"""

import os
import json
import uuid
import hmac
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from cryptography.fernet import Fernet

# Common sensitive patterns to mask (case-insensitive, normalized)
SENSITIVE_PATTERNS = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "cardnumber", "creditcard", "cvv", "cvc", "ssn", "socialsecurity",
    "authorization", "authtoken", "privatekey"
}

# Salt for payload hashing - no hardcoded fallback
_env_salt = os.getenv("AEGIS_PAYLOAD_SALT")
AEGIS_PAYLOAD_SALT: Optional[bytes] = _env_salt.encode("utf-8") if _env_salt else None


def get_payload_salt() -> bytes:
    """Retrieves payload salt from environment or fails closed unless auth is disabled."""
    salt = os.getenv("AEGIS_PAYLOAD_SALT")
    if not salt:
        if os.getenv("AEGIS_AUTH_DISABLED") == "1":
            return b"test_salt_unconfigured"
        raise RuntimeError("AEGIS_PAYLOAD_SALT environment variable is required")
    return salt.encode("utf-8")


def mask_sensitive_data(obj: Any) -> Any:
    """
    Recursively traverses arbitrary structures (nested dicts, lists, primitives)
    and redacts sensitive attributes using normalized case-insensitive matching.
    """
    if isinstance(obj, dict):
        masked = {}
        for k, v in obj.items():
            k_norm = str(k).lower().replace("-", "").replace("_", "").replace(" ", "")
            if any(pat in k_norm for pat in SENSITIVE_PATTERNS):
                masked[k] = "******REDACTED******"
            else:
                masked[k] = mask_sensitive_data(v)
        return masked
    elif isinstance(obj, list):
        return [mask_sensitive_data(item) for item in obj]
    return obj


def sanitize_errors(validation_errors: list[dict]) -> list[dict]:
    """Strips sensitive raw input and ctx keys from validation error dicts."""
    return [{k: v for k, v in err.items() if k not in ("input", "ctx")} for err in validation_errors]


class QuarantineDLQRouter:
    """Routes malformed payloads into an append-only forensic DLQ sink."""

    def __init__(self, dlq_dir: str = "data/dlq"):
        self.dlq_dir = Path(dlq_dir)
        self.dlq_dir.mkdir(parents=True, exist_ok=True)
        self.dlq_file = self.dlq_dir / "quarantine_events.jsonl"

    def record_quarantine_event(
        self,
        raw_bytes: bytes,
        contract_id: str,
        contract_version: str,
        validation_errors: list[dict],
        client_ip: str = "127.0.0.1",
    ) -> str:
        """
        Records an invalid or drifted event to the quarantine sink.
        Returns the generated forensic dlq_id.
        """
        dlq_id = f"dlq_{uuid.uuid4().hex[:12]}"
        ingested_at = datetime.now(timezone.utc).isoformat()
        
        # Salted HMAC-SHA256 to prevent rainbow-table brute-forcing of low-entropy payloads
        salt = get_payload_salt()
        salted_hash = hmac.new(salt, raw_bytes, hashlib.sha256).hexdigest()

        # Generate sanitized payload for human operator logs & triage dashboards
        try:
            raw_parsed = json.loads(raw_bytes.decode("utf-8"))
            sanitized_payload = mask_sensitive_data(raw_parsed)
        except Exception:
            sanitized_payload = {"raw_unparseable_hex": raw_bytes.hex()}

        # 0.1 Encrypt replay payload using Fernet
        replay_key = os.getenv("AEGIS_REPLAY_KEY")
        if not replay_key:
            raise RuntimeError("AEGIS_REPLAY_KEY environment variable is required to record DLQ events")
        fernet = Fernet(replay_key.encode("utf-8") if isinstance(replay_key, str) else replay_key)
        replay_payload_enc = fernet.encrypt(raw_bytes).decode("ascii")

        # 0.1 Strip input and ctx from validation errors
        cleaned_errors = sanitize_errors(validation_errors)

        # Build clean forensic record with separated human-sanitized vs encrypted machine-replay payloads
        forensic_record = {
            "dlq_id": dlq_id,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "ingested_at": ingested_at,
            "client_ip": client_ip,
            "payload_hmac_sha256": salted_hash,
            "validation_errors": cleaned_errors,
            "sanitized_payload": sanitized_payload,
            "replay_payload_enc": replay_payload_enc,
        }

        # Append-only write with default=str for bulletproof JSON serialization
        with open(self.dlq_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(forensic_record, default=str) + "\n")

        return dlq_id

    def read_quarantined_records(self, contract_id: Optional[str] = None) -> list[dict]:
        """Reads all quarantined records, optionally filtered by contract_id."""
        if not self.dlq_file.exists():
            return []

        results = []
        with open(self.dlq_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if contract_id is None or record.get("contract_id") == contract_id:
                        results.append(record)
        return results
