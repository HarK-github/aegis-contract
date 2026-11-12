# AegisContract: Dual-Boundary Data Contract & SQL AST Verification Engine

[![CI & Governance Gating](https://github.com/HarK-github/aegis-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/HarK-github/aegis-contract/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Pydantic V2](https://img.shields.io/badge/pydantic-v2_strict-green.svg)](https://docs.pydantic.dev/latest/)
[![SQLGlot AST](https://img.shields.io/badge/sqlglot-ast_compiler-orange.svg)](https://github.com/tobymao/sqlglot)
[![DuckDB](https://img.shields.io/badge/duckdb-analytical_engine-yellow.svg)](https://duckdb.org/)

> **Core Architectural Principle**: *Enforce strict contract boundaries at the edge; statically verify SQL transformations before warehouse execution.*

---

## 1. Executive Summary: The Dual-Boundary Problem

Data platforms break primarily across two unmonitored boundaries:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AEGISCONTRACT DUAL-BOUNDARY PLATFORM                                 │
├──────────────────────────────────────────┬─────────────────────────────────────────────────────────────┤
│      BOUNDARY 1: THE INGESTION EDGE      │            BOUNDARY 2: THE WAREHOUSE ENGINE                 │
│     (JSON / Protobuf Network Proxy)      │              (Catalog-Qualified SQL AST)                    │
├──────────────────────────────────────────┼─────────────────────────────────────────────────────────────┤
│ • Dynamic YAML -> Pydantic V2 Compiler   │ • Static SQL AST Analysis via `sqlglot`                     │
│ • Byte-level Strict Parsing (No Auto-Cast│ • Pre-compile dbt Jinja Mocking (Regex Approximation)       │
│ • HMAC Webhook Signature Verification    │ • Wildcard Guard (Prohibits `SELECT *` & `SELECT t.*`)      │
│ • Quarantine DLQ with Forensic Metadata  │ • Output Projection & Inferred Type Verification            │
│ • Salted HMAC Hash & Deep PII Redaction  │ • Dual-Perspective SemVer Diff Engine (Producer & Consumer) │
│ • 202 Accepted Ack & Idempotent Replay   │ • In-Warehouse Runtime Assertions (DuckDB Native Cursors)   │
└──────────────────────────────────────────┴─────────────────────────────────────────────────────────────┘
```

1. **The Ingestion Boundary (Network Edge)**: Client dev teams and third-party webhooks change payload shapes unannounced (e.g. integer IDs becoming strings, renamed fields, missing required attributes). Ingestion pipelines crash or downstream warehouse tables fill with silent `NULL`s.
2. **The Warehouse Boundary (SQL Transforms)**: Analytics engineers modify transformation models (CTEs, joins, window functions) that inadvertently drop or alter columns that downstream executive dashboards or ML feature stores depend on.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    subgraph Edge["Boundary 1: Ingestion Edge (FastAPI + Pydantic V2)"]
        ClientEmitter["Upstream Client Emitter<br/>(Stripe, Salesforce, Microservices)"] --> IngestProxy["Aegis Ingest Gateway<br/>(FastAPI Proxy)"]
        IngestProxy --> DynamicLoader["Dynamic Contract Loader<br/>(Compiles YAML to Pydantic)"]
        DynamicLoader --> StrictValidator{"Strict Byte Validation<br/>(model_validate_json)"}
        
        StrictValidator -- "Valid (200 OK)" --> CleanSink["Production Clean Stream<br/>(Local DuckDB / Parquet Bronze)"]
        StrictValidator -- "Drift / Schema Violation" --> DLQ["Quarantine DLQ (JSONL)<br/>• Forensic Metadata<br/>• Salted HMAC-SHA256 Hash<br/>• Deep PII Redaction<br/>• Segregated Replay Payload"]
        
        DLQ --> Ack["202 Accepted Ack<br/>(dlq_id returned)"]
        DLQ --> SlackAlert["Slack / PagerDuty Alert<br/>(Structured Schema Diff)"]
        
        DLQ --> ReplayWorker["Idempotent Replay Worker<br/>(SQLite Dedup Store)"]
        ReplayWorker -.-> IngestProxy
    end

    subgraph CI["Boundary 2A: CI/CD Developer Gating (SQL AST Linter)"]
        DevPR["Engineer SQL Pull Request<br/>(models/*.sql)"] --> ASTLinter["Catalog-Aware SQLGlot Linter"]
        Catalog["Warehouse Catalog<br/>(Table Types & Schemas)"] --> ASTLinter
        ContractYAML["Contract Definition<br/>(contracts/*.yaml)"] --> ASTLinter
        
        ASTLinter --> Decision{"Matches Declared<br/>Contract Schema & Types?"}
        Decision -- "Missing / Renamed Column / Wildcard" --> BlockPR["GitHub Actions Gating<br/>(Exit 1 + PR Comment)"]
        Decision -- "Conforming Projections" --> AllowMerge["Approve Merge (Exit 0)"]
    end

    subgraph Warehouse["Boundary 2B: Warehouse Runtime (DuckDB)"]
        CleanSink --> Staging["Staging Tables"]
        AllowMerge --> SQLTransform["SQL Transformation Models"]
        Staging --> SQLTransform
        SQLTransform --> TargetMart["Production Data Mart<br/>(fct_daily_orders)"]
        TargetMart --> RuntimeAssertion{"Runtime Assertions<br/>• PK Uniqueness<br/>• Numerical Bounds"}
        RuntimeAssertion -- "Violations > 0" --> QuarantinePartition["Halt Dashboards & Alert"]
    end
```

---

## 3. Core Capabilities & Realistic Engineering Trade-offs

### A. Dynamic Contract Compilation (Zero Code Duplication)
Contracts are authoritatively defined in YAML (`contracts/finance/orders_v1.yaml`). AegisContract compiles the schema into strict Pydantic V2 models at startup using `create_model`:
* **Raw Byte Strict Validation**: Uses `model_validate_json(raw_bytes)`, allowing valid ISO8601 strings and UUIDs to be parsed while strictly rejecting silent type coercions (e.g. `"123"` into integer `123`).
* **Rogue Field Protection**: Sets `extra="forbid"` to prevent unannounced field pollution.

### B. Forensic DLQ & Segregated Replay
* **Forensic Metadata**: Quarantined records capture exact validation errors (`loc`, `type`, `msg`), client IP, UTC timestamp, and a salted HMAC-SHA256 payload hash (preventing dictionary/rainbow table brute-forcing on low-entropy payloads).
* **Deep PII Redaction vs. Replay Paradox Resolved**: 
  - `sanitized_payload`: Sensitive attributes (`password`, `card_number`, `token`, `secret`, `ssn`) are recursively masked for human operator inspection and telemetry alerts.
  - `replay_payload_enc`: Encrypted raw bytes (Fernet) are preserved in an isolated machine-replay attribute so historical backfills heal authentic data rather than inserting asterisks into downstream tables.
* **Scope Note on PII**: Key-pattern masking redacts structured sensitive fields. Unstructured free-text PII (e.g. credit card numbers inside free-text user comments) requires external ML NER services and is outside the scope of this edge proxy.

### C. Catalog-Aware SQL AST Linter (`sqlglot`)
* **Wildcard Guard**: Detects and blocks raw wildcards (`SELECT *`) and qualified wildcards (`SELECT t.*`, `SELECT schema.t.*`) *before* AST qualification can expand them.
* **dbt Jinja Approximation**: Uses regex mocking for `{{ ref(...) }}`, `{{ source(...) }}`, `{{ this }}`, and control blocks (`{% set %}`, `{% if %}`). Documented explicitly as a static approximation that covers common models without requiring a full dbt compiler runtime.
* **Type Inference**: Qualifies CTE projections against base warehouse schemas using `sqlglot.optimizer.qualify` and `annotate_types`, flagging type mismatches (e.g. `FLOAT64` vs expected `NUMERIC`).

### D. Dual-Perspective Structural Contract Diff Engine (`diff_engine.py`)
Classifies contract version changes across two distinct vectors:
* **Producer SemVer**: What emitters are allowed to send (`MAJOR` = breaking, `MINOR` = additive, `PATCH` = metadata).
* **Consumer Blast Radius**: Evaluates whether producer additions (e.g. newly optional fields or expanded enum variants) break downstream ETL transforms, SQL queries, or ML models expecting non-null columns or exhaustive match clauses.

### E. In-Warehouse Runtime Assertions
Analytical databases often do not enforce primary key constraints at storage time. AegisContract executes native DuckDB runtime assertions (`order_id_unique` and `gross_revenue_positive`) directly against target tables without heavyweight dependencies.

---

## 4. Empirical Benchmark Scorecard (5-Run Statistical Median)

Evaluated against a synthetic 5,000-event benchmark stream featuring **472 injected schema-drift events across 4 classes** (type drift, field rename, null violation, range violation).

**Hardware Environment**: Linux 7.0.0-43-generic, x86_64, 16 vCPUs.

```
=================================================================
               AEGISCONTRACT BENCHMARK SCORECARD                 
=================================================================
• Total Events Processed:        5,000
• Clean Accepted:                4,528
• Quarantined Drift:             472
• False Positives / Negatives:   0 / 0
-----------------------------------------------------------------
📊 Profile 1: Core Pydantic V2 In-Memory Validation (5-Run Median):
   - p50 (Median Latency):       6.60 µs
   - Mean Latency:               7.20 µs
   - Core Processing Speed:      ~69,800 events/sec (Single Core)
-----------------------------------------------------------------
🌐 Profile 2: In-Process ASGI Gateway + DLQ Disk I/O (5-Run Median):
   - p50 (Median Latency):       3.08 ms
   - Mean Latency:               3.15 ms
   - In-Process Throughput:      ~290 requests/sec (Single Thread)
=================================================================
```

> **Scope Note on Metrics**: Structural precision and recall hold for schema violations defined in the contract. Schema validation cannot detect semantic unit shifts (e.g. cents sent as whole dollars), lowercase `"usd"`, or statistical distribution drift.

---

## 5. Quickstart & Local Reproduction

The entire platform runs locally in a clean virtual environment with zero cloud credentials.

### 1. Installation
```bash
git clone https://github.com/HarK-github/aegis-contract.git
cd aegis-contract
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Test Suite (31 Tests Passing, 0 Warnings)
```bash
pytest -v
```

### 3. Verify Real Source Mutation Protection
```bash
# Temporarily mutate source code to test test coverage
sed -i 's/extra="forbid"/extra="ignore"/' src/edge/contract_loader.py
pytest -q tests/test_contract_loader.py  # MUST FAIL with AssertionError
git checkout src/edge/contract_loader.py  # Restore clean source
```

---

## 7. Author & License

- **Author**: Harshit Kandpal ([@HarK-github](https://github.com/HarK-github))
- **License**: Apache-2.0
