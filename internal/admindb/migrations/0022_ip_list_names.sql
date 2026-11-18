-- Names let rules write client.ip_lists and never change, so a rule can't
-- silently stop matching. wide keeps ranges up to /8 for IPv4 and /16 for
-- IPv6. A default list is wide only where the provider's own data has such
-- ranges, so a bad upstream file cannot widen a monitor or crawler list,
-- which rules use as exclusions. Rows added before this migration keep their
-- id, enabled state and wide=false (widening an enabled row would change what
-- it matches with no audit row); a row on a default URL takes the default's
-- name, any other row is named list-<id>.
ALTER TABLE denylist_sources ADD COLUMN name text, ADD COLUMN wide boolean NOT NULL DEFAULT false;

-- Default lists, all off: people turn on the ones their rules name. Like the
-- role grants in the earlier migration, this migration is their record (no
-- audit row); every later change is audited. Provider lists are
-- rezmoss/cloud-provider-ip-addresses (CC0), updated daily.
CREATE TEMP TABLE default_ip_lists (name text, url text, wide boolean) ON COMMIT DROP;
INSERT INTO default_ip_lists VALUES
    ('firehol-abusers', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_30d.netset', false),
    ('spamhaus-drop', 'https://www.spamhaus.org/drop/drop.txt', false),
    ('akamai', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/akamai/akamai_ips_merged.txt', true),
    ('alibaba', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/alibaba/alibaba_ips_merged.txt', true),
    ('amazonbot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/amazonbot/amazonbot_ips_merged.txt', false),
    ('apple-private-relay', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/apple_private_relay/apple_private_relay_ips_merged.txt', false),
    ('applebot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/applebot/applebot_ips_merged.txt', false),
    ('atlassian', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/atlassian/atlassian_ips_merged.txt', false),
    ('aws', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/aws/aws_ips_merged.txt', true),
    ('azure', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/azure/azure_ips_merged.txt', true),
    ('backblaze', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/backblaze/backblaze_ips_merged.txt', false),
    ('baidu', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/baidu/baidu_ips_merged.txt', true),
    ('bingbot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/bingbot/bingbot_ips_merged.txt', false),
    ('bunny', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/bunny/bunny_ips_merged.txt', false),
    ('cachefly', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/cachefly/cachefly_ips_merged.txt', false),
    ('circleci', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/circleci/circleci_ips_merged.txt', false),
    ('claudebot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/claudebot/claudebot_ips_merged.txt', false),
    ('cloudflare', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/cloudflare/cloudflare_ips_merged.txt', true),
    ('commoncrawl', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/commoncrawl/commoncrawl_ips_merged.txt', false),
    ('contabo', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/contabo/contabo_ips_merged.txt', true),
    ('datadog', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/datadog/datadog_ips_merged.txt', false),
    ('digitalocean', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/digitalocean/digitalocean_ips_merged.txt', false),
    ('discord', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/discord/discord_ips_merged.txt', false),
    ('duckduckbot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/duckduckbot/duckduckbot_ips_merged.txt', false),
    ('fastly', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/fastly/fastly_ips_merged.txt', true),
    ('gabia', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/gabia/gabia_ips_merged.txt', false),
    ('gcore', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/gcore/gcore_ips_merged.txt', false),
    ('github', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/github/github_ips_merged.txt', true),
    ('gocache', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/gocache/gocache_ips_merged.txt', false),
    ('googlebot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/googlebot/googlebot_ips_merged.txt', false),
    ('googlecloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/googlecloud/googlecloud_ips_merged.txt', true),
    ('googleservices', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/googleservices/googleservices_ips_merged.txt', true),
    ('gptbot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/gptbot/gptbot_ips_merged.txt', false),
    ('hetzner', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/hetzner/hetzner_ips_merged.txt', true),
    ('hostway', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/hostway/hostway_ips_merged.txt', false),
    ('huawei', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/huawei/huawei_ips_merged.txt', true),
    ('ibmcloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/ibmcloud/ibmcloud_ips_merged.txt', true),
    ('imperva', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/imperva/imperva_ips_merged.txt', true),
    ('internetarchive', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/internetarchive/internetarchive_ips_merged.txt', false),
    ('leaseweb', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/leaseweb/leaseweb_ips_merged.txt', true),
    ('linode', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/linode/linode_ips_merged.txt', true),
    ('meta', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/meta/meta_ips_merged.txt', true),
    ('microsoft365', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/microsoft365/microsoft365_ips_merged.txt', true),
    ('mullvad', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/mullvad/mullvad_ips_merged.txt', false),
    ('nhncloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/nhncloud/nhncloud_ips_merged.txt', false),
    ('oracle', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/oracle/oracle_ips_merged.txt', true),
    ('ovhcloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/ovhcloud/ovhcloud_ips_merged.txt', true),
    ('perplexitybot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/perplexitybot/perplexitybot_ips_merged.txt', false),
    ('pingdom', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/pingdom/pingdom_ips_merged.txt', false),
    ('play2go', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/play2go/play2go_ips_merged.txt', false),
    ('quiccloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/quiccloud/quiccloud_ips_merged.txt', false),
    ('rackspace', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/rackspace/rackspace_ips_merged.txt', true),
    ('salesforce', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/salesforce/salesforce_ips_merged.txt', true),
    ('scaleway', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/scaleway/scaleway_ips_merged.txt', true),
    ('statuscake', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/statuscake/statuscake_ips_merged.txt', false),
    ('stormwall', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/stormwall/stormwall_ips_merged.txt', false),
    ('sucuri', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/sucuri/sucuri_ips_merged.txt', false),
    ('teamcity', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/teamcity/teamcity_ips_merged.txt', false),
    ('telegram', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/telegram/telegram_ips_merged.txt', false),
    ('tencent', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/tencent/tencent_ips_merged.txt', true),
    ('tor', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/tor/tor_ips_merged.txt', false),
    ('upcloud', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/upcloud/upcloud_ips_merged.txt', true),
    ('uptimerobot', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/uptimerobot/uptimerobot_ips_merged.txt', false),
    ('vultr', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/vultr/vultr_ips_merged.txt', true),
    ('wasabi', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/wasabi/wasabi_ips_merged.txt', false),
    ('yandex', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/yandex/yandex_ips_merged.txt', true),
    ('zoho', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/zoho/zoho_ips_merged.txt', false),
    ('zoom', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/zoom/zoom_ips_merged.txt', false),
    ('zscaler', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/zscaler/zscaler_ips_merged.txt', true),
    ('aws-ec2', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/aws/services/ec2/aws_ec2_ips_merged.txt', true),
    ('aws-route53-healthchecks', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/aws/services/route53_healthchecks/aws_route53_healthchecks_ips_merged.txt', false),
    ('github-hooks', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/github/services/hooks/github_hooks_ips_merged.txt', true),
    ('github-actions', 'https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/github/services/actions/github_actions_ips_merged.txt', true);

UPDATE denylist_sources s SET name = d.name FROM default_ip_lists d WHERE s.url = d.url;
UPDATE denylist_sources SET name = 'list-' || id WHERE name IS NULL;

ALTER TABLE denylist_sources
    ALTER COLUMN name SET NOT NULL,
    ADD CONSTRAINT denylist_sources_name_key UNIQUE (name),
    ADD CONSTRAINT denylist_sources_name_check CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$');

INSERT INTO denylist_sources (name, url, enabled, wide, added_by, added_at)
SELECT name, url, false, wide, 'migration', now() FROM default_ip_lists
ON CONFLICT (url) DO NOTHING;
