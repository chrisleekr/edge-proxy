-- IP lists hold addresses to allow as well as to block, so their tables and
-- permission are named for what they hold. Grants follow a renamed table.
ALTER TABLE denylist_sources RENAME TO ip_lists;
ALTER TABLE denylist_sets RENAME TO ip_list_sets;
ALTER TABLE denylist_status RENAME TO ip_list_status;
ALTER SEQUENCE denylist_sources_id_seq RENAME TO ip_lists_id_seq;
UPDATE role_permissions SET permission = 'ip_lists.manage' WHERE permission = 'denylists.manage';

-- A list with no URL holds addresses typed in admin. It is never fetched:
-- saving it writes its ip_list_sets row in the same transaction. Postgres
-- treats NULLs as distinct, so the URL stays unique among downloaded lists.
ALTER TABLE ip_lists ALTER COLUMN url DROP NOT NULL;
