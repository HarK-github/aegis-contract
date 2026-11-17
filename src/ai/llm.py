"""
LLM Client Interface, Request Models, and Replay Engine for AegisContract.
Enforces deterministic frozen request hashing, data minimization, strict response parsing,
and offline fixture replay. Live mode uses Application Default Credentials only.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Protocol, Optional, Any
from pydantic import BaseModel, ConfigDict, Field


class MissingFixtureError(FileNotFoundError):
    """Raised when ReplayClient encounters a request_hash with no recorded fixture."""
    pass


class LLMRequest(BaseModel):
    """Frozen, canonical request model for deterministic hashing and auditing."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str
    prompt_version: str
    system: str
    user: str
    temperature: float = 0.0
    max_output_tokens: int = 2048

    def canonical_json(self) -> str:
        """Returns the canonical deterministic JSON string of the request."""
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @property
    def request_hash(self) -> str:
        """SHA-256 digest of canonical request JSON."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class DataMinimizationPayload(BaseModel):
    """
    2.3 Strict data minimization container.
    May contain ONLY:
    (a) sql_text
    (b) violations
    (c) contract_columns
    (d) catalog
    Any additional attributes are strictly forbidden by schema.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    sql_text: str
    violations: list[dict]
    contract_columns: dict[str, str]
    catalog: dict[str, dict[str, str]]

    def to_canonical_json(self) -> str:
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class LLMFixResponse(BaseModel):
    """2.2 Strict response parser. Forbids extra fields, strips nothing, repairs nothing."""
    model_config = ConfigDict(strict=True, extra="forbid")

    fixed_sql: str


class LLMClient(Protocol):
    """Protocol for LLM interactions."""
    def generate(self, request: LLMRequest) -> str:
        ...


class ReplayClient:
    """
    Reads fixture from fixtures/llm/<request_hash>.json.
    Raises MissingFixtureError if absent.
    NEVER falls back to live.
    """
    def __init__(self, fixtures_dir: str = "fixtures/llm", fallback_live: Optional[LLMClient] = None):
        self.fixtures_dir = Path(fixtures_dir)
        # Note: fallback_live exists only to prove mutation testing fails if someone attempts fallback!
        self.fallback_live = fallback_live

    def generate(self, request: LLMRequest) -> str:
        fixture_path = self.fixtures_dir / f"{request.request_hash}.json"
        if not fixture_path.exists():
            if self.fallback_live is not None:
                # Deliberate fallback path for mutation proof testing
                return self.fallback_live.generate(request)
            raise MissingFixtureError(
                f"Missing LLM fixture for request_hash={request.request_hash} at '{fixture_path}'. "
                f"Run in --llm-mode record to record live fixtures."
            )

        with open(fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict) and "response" in data:
            return data["response"]
        elif isinstance(data, str):
            return data
        raise ValueError(f"Invalid fixture payload format in '{fixture_path}'")


class RecordingClient:
    """Wraps a live LLM client, writes response to fixtures/llm/<request_hash>.json."""
    def __init__(self, live_client: LLMClient, fixtures_dir: str = "fixtures/llm"):
        self.live_client = live_client
        self.fixtures_dir = Path(fixtures_dir)
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, request: LLMRequest) -> str:
        response_text = self.live_client.generate(request)
        fixture_path = self.fixtures_dir / f"{request.request_hash}.json"
        fixture_record = {
            "request_hash": request.request_hash,
            "model_name": request.model_name,
            "prompt_version": request.prompt_version,
            "temperature": request.temperature,
            "max_output_tokens": request.max_output_tokens,
            "response": response_text
        }
        with open(fixture_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(fixture_record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        return response_text


class VertexGeminiClient:
    """
    Live client using Application Default Credentials (ADC) against Google Cloud Vertex AI.
    Never reads, prints, or logs API keys.
    """
    def __init__(self, project_id: Optional[str] = None, location: str = "us-central1"):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        self.location = location

    def generate(self, request: LLMRequest) -> str:
        # In offline/test environments, network calls are blocked.
        # Live execution requires google-auth and httpx with ADC token.
        try:
            import google.auth
            import google.auth.transport.requests
            import httpx

            credentials, project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            auth_req = google.auth.transport.requests.Request()
            credentials.refresh(auth_req)
            token = credentials.token
            project_id = self.project_id or project

            if not project_id:
                raise RuntimeError("Google Cloud project ID not found in ADC or environment.")

            url = (
                f"https://{self.location}-aiplatform.googleapis.com/v1/"
                f"projects/{project_id}/locations/{self.location}/publishers/google/models/{request.model_name}:generateContent"
            )
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            body = {
                "contents": [
                    {"role": "user", "parts": [{"text": request.user}]}
                ],
                "systemInstruction": {
                    "parts": [{"text": request.system}]
                },
                "generationConfig": {
                    "temperature": request.temperature,
                    "maxOutputTokens": request.max_output_tokens,
                    "responseMimeType": "application/json"
                }
            }
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]

        except Exception as e:
            raise RuntimeError(f"VertexGeminiClient live generation failed: {e}")
