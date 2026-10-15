-- Owner runs migrations; the app role is what admin connects as.
CREATE ROLE edge_owner LOGIN PASSWORD 'owner';
CREATE ROLE edge_app LOGIN PASSWORD 'app';
CREATE DATABASE edge_admin OWNER edge_owner;
REVOKE ALL ON DATABASE edge_admin FROM PUBLIC;
GRANT CONNECT ON DATABASE edge_admin TO edge_app;
