CREATE TABLE IF NOT EXISTS contacts (
    installation_key BLOB NOT NULL,
    kind INTEGER NOT NULL,
    PRIMARY KEY (installation_key, kind)
);
