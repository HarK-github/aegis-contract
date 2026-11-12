WITH staged AS (
    SELECT 
        order_id,
        tenant_id,
        amount_cents / 100.0 AS gross_revenue,
        created_at AS order_timestamp
    FROM raw_orders
)
SELECT 
    s.order_id,
    s.tenant_id,
    s.gross_revenue,
    s.order_timestamp
FROM staged s
