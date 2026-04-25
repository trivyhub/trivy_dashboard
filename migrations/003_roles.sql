ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'member';

-- Le premier user d'une org est toujours owner
UPDATE users SET role = 'owner'
WHERE id IN (
    SELECT DISTINCT ON (organization_id) id
    FROM users
    ORDER BY organization_id, created_at ASC
);
