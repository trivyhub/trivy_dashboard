ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS primary_url VARCHAR(512);
