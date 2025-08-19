CREATE TABLE clients (
  id    UUID  PRIMARY KEY,
  name  TEXT  NOT NULL
);

CREATE TABLE credentials (
  api_key             UUID  PRIMARY KEY,
  client_id           UUID  REFERENCES clients(id),
  encrypted_secret    TEXT  NOT NULL,
  encrypted_data_key  TEXT  NOT NULL
);

CREATE TABLE users (
  id                    UUID  PRIMARY KEY,
  client_id             UUID  REFERENCES clients(id),
  encrypted_private_key TEXT  NOT NULL,
  encrypted_data_key    TEXT  NOT NULL
);