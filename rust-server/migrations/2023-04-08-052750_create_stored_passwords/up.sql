CREATE TABLE stored_passwords (
  id INTEGER AUTO_INCREMENT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  purpose VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  UNIQUE KEY user_id_purpose_unique_constraint (user_id, purpose)
);