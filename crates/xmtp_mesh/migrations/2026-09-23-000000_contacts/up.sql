-- Welcome relationships, per installation (§B5.2 Rule A scoping).
-- kind 0: we delivered a welcome to installation_key (it acknowledged it).
-- kind 1: installation_key delivered a welcome to us.
CREATE TABLE contacts (
    installation_key BLOB NOT NULL,
    kind INTEGER NOT NULL,
    PRIMARY KEY (installation_key, kind)
);
