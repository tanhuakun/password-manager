CREATE TABLE users_oauth (
  id INTEGER AUTO_INCREMENT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ,
  oauth_id VARCHAR(255) NOT NULL,
  oauth_provider VARCHAR(255) NOT NULL,
  CONSTRAINT unique_oauth_id_provider
    UNIQUE (oauth_id, oauth_provider)
);