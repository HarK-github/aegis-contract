SELECT 
    order_id,
    tenant_id,
    created_at AS order_timestamp
FROM raw_orders
