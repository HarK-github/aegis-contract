"""
Benchmark Stream Generator for AegisContract.
Generates 5,000 synthetic e-commerce events with 10% controlled schema mutations
across the 5 enterprise failure modes:
1. Baseline Conforming (90%)
2. Type Drift (customer_id as string) (2.5%)
3. Field Rename (amount_cents -> total_amount_cents) (2.5%)
4. Nullability Violation (currency: null) (2.5%)
5. Out-of-Bounds Semantic Violation (amount_cents <= 0) (2.5%)
"""

import json
import uuid
import random
from pathlib import Path
from datetime import datetime, timezone

OUTPUT_PATH = Path("data/benchmark_stream.jsonl")


def generate_benchmark_dataset(num_events: int = 5000, seed: int = 42):
    random.seed(seed)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    currencies = ["USD", "EUR", "GBP", "INR"]
    tenants = ["org_a912bc01", "org_b823cd02", "org_c734de03"]

    scenarios_counts = {
        "baseline_valid": 0,
        "type_drift": 0,
        "field_rename": 0,
        "null_violation": 0,
        "semantic_violation": 0
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for i in range(num_events):
            roll = random.random()
            if roll < 0.90:
                scenario = "baseline_valid"
            elif roll < 0.925:
                scenario = "type_drift"
            elif roll < 0.950:
                scenario = "field_rename"
            elif roll < 0.975:
                scenario = "null_violation"
            else:
                scenario = "semantic_violation"

            scenarios_counts[scenario] += 1

            # Base conforming payload
            payload = {
                "event_id": str(uuid.uuid4()),
                "tenant_id": random.choice(tenants),
                "customer_id": random.randint(1000, 99999),
                "amount_cents": random.randint(500, 75000),
                "currency": random.choice(currencies),
                "event_timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Inject controlled mutation
            if scenario == "type_drift":
                payload["customer_id"] = f"CUST_{payload['customer_id']}"
            elif scenario == "field_rename":
                payload["total_amount_cents"] = payload.pop("amount_cents")
            elif scenario == "null_violation":
                payload["currency"] = None
            elif scenario == "semantic_violation":
                payload["amount_cents"] = -random.randint(100, 5000)

            record = {
                "record_index": i,
                "intended_scenario": scenario,
                "is_corrupted": (scenario != "baseline_valid"),
                "payload": payload
            }
            f.write(json.dumps(record) + "\n")

    print(f"✅ Generated {num_events} benchmark events at {OUTPUT_PATH}:")
    for s, count in scenarios_counts.items():
        print(f"   • {s:<20}: {count:>5} ({count/num_events*100:.1f}%)")


if __name__ == "__main__":
    generate_benchmark_dataset()
