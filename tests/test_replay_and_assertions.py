import json
import duckdb
import pytest
from src.edge.replay import DLQReplayWorker, ReplayStateStore
from src.edge.contract_loader import compile_contract_from_yaml
from src.warehouse.runtime_assertions import WarehouseAssertionRunner


def test_idempotent_replay_worker(tmp_path):
    db_file = tmp_path / "test_replay.db"
    state_store = ReplayStateStore(db_path=str(db_file))
    worker = DLQReplayWorker(state_store=state_store)

    contract = compile_contract_from_yaml("contracts/finance/orders_v1.yaml")

    # Simulate 2 quarantined records: 1 healable, 1 still invalid
    dlq_records = [
        {
            "dlq_id": "dlq_001",
            "raw_payload": {
                "event_id": "b1111111-1111-1111-1111-111111111111",
                "tenant_id": "org_a912bc01",
                "customer_id": 501,
                "amount_cents": 2500,
                "currency": "USD",
                "event_timestamp": "2026-11-17T15:00:00Z"
            }
        },
        {
            "dlq_id": "dlq_002",
            "raw_payload": {
                "event_id": "b2222222-2222-2222-2222-222222222222",
                "tenant_id": "org_a912bc01",
                "customer_id": "NOT_AN_INT",  # Still invalid
                "amount_cents": 2500,
                "currency": "USD",
                "event_timestamp": "2026-11-17T15:00:00Z"
            }
        }
    ]

    healed_sink = []
    def sink_fn(event):
        healed_sink.append(event)

    # First replay run
    res1 = worker.replay(
        dlq_records=dlq_records,
        contract_validator_fn=contract.validate_bytes,
        target_sink_fn=sink_fn,
        dry_run=False
    )

    assert res1["healed"] == 1
    assert res1["still_failing"] == 1
    assert res1["skipped_duplicates"] == 0
    assert len(healed_sink) == 1
    assert healed_sink[0]["_replayed_metadata"]["is_replayed"] is True

    # Second replay run with identical records: MUST be skipped due to idempotency!
    res2 = worker.replay(
        dlq_records=dlq_records,
        contract_validator_fn=contract.validate_bytes,
        target_sink_fn=sink_fn,
        dry_run=False
    )

    assert res2["healed"] == 0
    assert res2["skipped_duplicates"] == 1  # Deduplicated!
    assert len(healed_sink) == 1  # No duplicate inserts


def test_warehouse_runtime_assertions():
    con = duckdb.connect(":memory:")

    # Create analytical staging table without DDL PK enforcement
    # (resembling BigQuery / Snowflake where primary keys are informational metadata)
    con.execute("""
        CREATE TABLE fct_daily_orders (
            order_id VARCHAR,
            tenant_id VARCHAR,
            gross_revenue DOUBLE,
            order_timestamp TIMESTAMP
        );
        INSERT INTO fct_daily_orders VALUES 
            ('ord_1', 'org_1', 49.99, '2026-11-17 10:00:00'),
            ('ord_2', 'org_1', 19.50, '2026-11-17 11:00:00');
    """)

    contract_spec = {
        "warehouse_model": {"target_table": "fct_daily_orders"},
        "runtime_assertions": [
            {
                "name": "order_id_unique",
                "query": "SELECT COUNT(order_id) - COUNT(DISTINCT order_id) AS dupes FROM {{ target }}",
                "expected_field": "dupes",
                "expected_value": 0
            },
            {
                "name": "gross_revenue_positive",
                "query": "SELECT COUNT(*) AS bad_rows FROM {{ target }} WHERE gross_revenue <= 0",
                "expected_field": "bad_rows",
                "expected_value": 0
            }
        ]
    }

    runner = WarehouseAssertionRunner(connection=con)
    results = runner.run_assertions_for_contract(contract_spec)
    assert all(r.passed for r in results)

    # Now inject corrupted data: duplicate PK ('ord_1') and negative revenue (-10.00)
    con.execute("""
        INSERT INTO fct_daily_orders VALUES 
            ('ord_1', 'org_1', -10.00, '2026-11-17 12:00:00');
    """)

    corrupted_results = runner.run_assertions_for_contract(contract_spec)
    pk_assertion = next(r for r in corrupted_results if r.assertion_name == "order_id_unique")
    rev_assertion = next(r for r in corrupted_results if r.assertion_name == "gross_revenue_positive")

    assert pk_assertion.passed is False
    assert pk_assertion.actual_value == 1  # 1 duplicate detected
    assert rev_assertion.passed is False
    assert rev_assertion.actual_value == 1  # 1 bad row with <= 0 revenue detected
