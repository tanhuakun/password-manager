ALTER TABLE users
ADD COLUMN totp_enabled BOOLEAN NOT NULL,
ADD COLUMN totp_base32 VARCHAR(64);
