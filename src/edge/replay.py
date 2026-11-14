"""
Idempotent DLQ Replay Worker for AegisContract.
Reads quarantined events, validates them against updated contracts,
and replays them with strict deduplication and forensic audit metadata.
Extracts unmasked payloads from replay_payload_b64 to prevent backfilling redacted strings.
"""

import os
import json
import base64
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable
from cryptography.fernet import Fernet


class ReplayStateStore:
    """SQLite-backed deduplication store for idempotent replays."""

    def __init__(self, db_path: str = "data/replay_state.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replayed_events (
                    dedup_key TEXT PRIMARY KEY,
                    dlq_id TEXT,
                    replayed_at TEXT
                )
            """)
            conn.commit()

    def has_replayed(self, dedup_key: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM replayed_events WHERE dedup_key = ?", (dedup_key,))
            return cursor.fetchone() is not None

    def mark_replayed(self, dedup_key: str, dlq_id: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO replayed_events (dedup_key, dlq_id, replayed_at) VALUES (?, ?, ?)",
                (dedup_key, dlq_id, now)
            )
            conn.commit()


class DLQReplayWorker:
    """Orchestrates safe, deduplicated replay of quarantined events."""

    def __init__(self, state_store: Optional[ReplayStateStore] = None):
        self.state_store = state_store or ReplayStateStore()

    def replay(
        self,
        dlq_records: list[dict],
        contract_validator_fn: Callable[[bytes], tuple[bool, Optional[dict], Optional[list]]],
        target_sink_fn: Optional[Callable[[dict], None]] = None,
        dry_run: bool = False
    ) -> dict:
        """
        Replays quarantined records through the updated contract validator.
        Returns a summary report of healed, skipped, and still-failing records.
        """
        healed_count = 0
        skipped_duplicate_count = 0
        still_failing_count = 0
        healed_events = []

        for record in dlq_records:
            dlq_id = record.get("dlq_id", "unknown")

            # Extract unmasked payload for machine replay
            if "replay_payload_enc" in record and record["replay_payload_enc"]:
                try:
                    replay_key = os.getenv("AEGIS_REPLAY_KEY")
                    if not replay_key:
                        raise RuntimeError("AEGIS_REPLAY_KEY is required to decrypt replay payloads")
                    fernet = Fernet(replay_key.encode("utf-8") if isinstance(replay_key, str) else replay_key)
                    raw_bytes = fernet.decrypt(record["replay_payload_enc"].encode("ascii"))
                    raw_payload = json.loads(raw_bytes.decode("utf-8"))
                except Exception:
                    raw_payload = record.get("sanitized_payload", record.get("raw_payload", {}))
                    raw_bytes = json.dumps(raw_payload).encode("utf-8")
            elif "replay_payload_b64" in record and record["replay_payload_b64"]:
                try:
                    raw_bytes = base64.b64decode(record["replay_payload_b64"])
                    raw_payload = json.loads(raw_bytes.decode("utf-8"))
                except Exception:
                    raw_payload = record.get("sanitized_payload", record.get("raw_payload", {}))
                    raw_bytes = json.dumps(raw_payload).encode("utf-8")
            else:
                raw_payload = record.get("sanitized_payload", record.get("raw_payload", {}))
                raw_bytes = json.dumps(raw_payload).encode("utf-8")

            # Determine deduplication key (prefer tenant:event_id, fallback to sha256)
            tenant_id = raw_payload.get("tenant_id", "default")
            event_id = raw_payload.get("event_id") or record.get("payload_hmac_sha256")
            dedup_key = f"{tenant_id}:{event_id}"

            # Check if already replayed (idempotency barrier)
            if self.state_store.has_replayed(dedup_key):
                skipped_duplicate_count += 1
                continue

            # Re-validate with new/updated contract
            is_valid, validated_data, errors = contract_validator_fn(raw_bytes)

            if is_valid and validated_data:
                # Inject forensic audit metadata
                validated_data["_replayed_metadata"] = {
                    "is_replayed": True,
                    "replayed_at": datetime.now(timezone.utc).isoformat(),
                    "source_dlq_id": dlq_id,
                }
                healed_count += 1
                healed_events.append(validated_data)

                if not dry_run:
                    if target_sink_fn:
                        target_sink_fn(validated_data)
                    self.state_store.mark_replayed(dedup_key, dlq_id)
            else:
                still_failing_count += 1

        return {
            "dry_run": dry_run,
            "total_processed": len(dlq_records),
            "healed": healed_count,
            "skipped_duplicates": skipped_duplicate_count,
            "still_failing": still_failing_count,
            "healed_events": healed_events if dry_run else []
        }
