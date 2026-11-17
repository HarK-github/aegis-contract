WITH prep AS (
    SELECT id FROM source_data
)
SELECT id, unprojected_cte_field
FROM prep
