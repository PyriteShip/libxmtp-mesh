-- Group traffic is scoped by group membership (from the local libxmtp
-- client), not by welcome relationships: the contacts table is unused.
DROP TABLE IF EXISTS contacts;
