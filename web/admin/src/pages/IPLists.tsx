import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api';
import { Badge, Button, Card, Check, ConfirmButton, ErrorBox, Input, Notice, Page, Pending, Table, ago, plural, when } from '../ui';

// The IP lists page: lists admin downloads for client.ip_lists, and the
// IPs edges banned. Every number comes from admin.

interface Source {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  wide: boolean;
  added_by: string;
  added_at: string;
  entries: number;
  fetched_at: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  failures: number;
  last_error: string;
  skipped: number;
}

interface Ban {
  ip: string;
  rule: string;
  host: string;
  path: string;
  started_at: string;
  ends_at: string;
  edge: string;
  lift_pending: boolean;
}

export const denylistsQuery = { queryKey: ['denylists'], queryFn: () => api<Source[]>('GET', '/api/denylists'), refetchInterval: 60_000 };

function stateOf(s: Source) {
  if (!s.enabled) return { tone: 'slate', words: 'off' } as const;
  if (s.entries === 0) return s.failures > 0 ? ({ tone: 'red', words: 'failing, no list yet' } as const) : ({ tone: 'slate', words: 'not fetched yet' } as const);
  if (s.failures > 0) return { tone: 'amber', words: 'failing, using the last good list' } as const;
  return { tone: 'green', words: 'up to date' } as const;
}

export function IPLists({ canManage }: { canManage: boolean }) {
  return (
    <Page
      title="IP lists"
      info={'Named lists of addresses, such as abusers or a cloud provider, and the addresses edges banned. A rule matches a list by its name, for example client.ip_lists in {"aws"}; a trap rule bans an address on every host.'}
    >
      <Lists canManage={canManage} />
      <Bans canManage={canManage} />
    </Page>
  );
}

function Lists({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery(denylistsQuery);
  const [name, setName] = useState('');
  const [url, setURL] = useState('');
  const [wide, setWide] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ['denylists'] });
  const add = useMutation({
    mutationFn: () => api('POST', '/api/denylists', { name: name.trim(), url: url.trim(), wide }),
    onSuccess: () => (setName(''), setURL(''), setWide(false), void refresh()),
  });
  const change = useMutation({
    mutationFn: (a: { method: string; path: string; body?: unknown }) => api(a.method, a.path, a.body),
    onSuccess: () => void refresh(),
  });
  const rows = q.data ?? [];
  return (
    <Card
      id="lists"
      title="Lists"
      intro={'Rules match a list by its name, such as client.ip_lists in {"aws"}. Only lists that are on are matched. Admin downloads each list that is on about once an hour and keeps the last good copy. A change reaches every edge within about a minute, without a publish.'}
      info="A list is one address or range per line; text after a space, a semicolon or a hash is ignored. Ranges wider than a /16 for IPv4 or a /32 for IPv6 are skipped, or wider than a /8 and a /16 on a list that allows wide ranges. Entry counts are exact: they count the ranges kept, after repeats are removed. A failed download changes nothing on the edges: they keep the last good list. At most 128 lists, and edges take at most 500,000 entries in all. Lists are taken in the order they were added, and one that would pass that is left out whole."
    >
      <div className="flex flex-col gap-4">
        <ErrorBox error={q.error ?? change.error} />
        {!q.data && !q.error && <Pending error={undefined} />}
        {q.data && rows.length === 0 && <p className="text-body">No lists. Rules that read client.ip_lists match no one until one is added.</p>}
        {rows.length > 0 && (
          <Table head={['Name', 'Address', 'State', 'Entries', 'Updated', 'Last try', '']} num={[3]}>
            {rows.map((s) => {
              const st = stateOf(s);
              return (
                <tr key={s.id} className="align-top">
                  <td className="font-mono">{s.name}</td>
                  <td className="min-w-64 whitespace-normal">
                    {/* Only the URL may break anywhere; the notes under it wrap at words. */}
                    <span className="font-mono break-all">{s.url}</span>
                    {s.wide && <p className="font-sans text-body">Allows ranges up to /8.</p>}
                    {s.failures > 0 && s.last_error && <p className="font-sans break-words text-body">Last error: {s.last_error}</p>}
                    {s.skipped > 0 && <p className="font-sans text-body">{plural(s.skipped, 'line')} of the last download could not be used and were skipped.</p>}
                  </td>
                  <td>
                    <Badge tone={st.tone}>{st.words}</Badge>
                  </td>
                  <td className="text-right tabular-nums">{s.entries === 0 ? 'none' : s.entries.toLocaleString()}</td>
                  <td>{s.fetched_at ? <span title={when(s.fetched_at)}>{ago(s.fetched_at)}</span> : 'never'}</td>
                  <td>{s.last_attempt_at ? <span title={when(s.last_attempt_at)}>{ago(s.last_attempt_at)}</span> : 'due'}</td>
                  <td>
                    {canManage && (
                      <div className="flex flex-wrap gap-2">
                        <Button disabled={change.isPending || !s.enabled} onClick={() => change.mutate({ method: 'POST', path: `/api/denylists/${s.id}/refresh` })}>
                          Refresh now
                        </Button>
                        <Button disabled={change.isPending} onClick={() => change.mutate({ method: 'PATCH', path: `/api/denylists/${s.id}`, body: { enabled: !s.enabled } })}>
                          {s.enabled ? 'Turn off' : 'Turn on'}
                        </Button>
                        <ConfirmButton
                          variant="danger"
                          title="Remove this list?"
                          action="Remove"
                          confirm={<>Edges drop {s.name} from <code>client.ip_lists</code> within about a minute, without a publish: a rule that requires it matches no one, and an exclusion that names it excludes no one.</>}
                          onConfirm={() => change.mutate({ method: 'DELETE', path: `/api/denylists/${s.id}` })}
                        >
                          Remove
                        </ConfirmButton>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
        {canManage && (
          <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => (e.preventDefault(), add.mutate())}>
            <Input
              label="Name"
              className="min-w-40"
              placeholder="aws"
              hint="What rules write. Lowercase letters, digits and hyphens. It cannot change."
              pattern="[a-z0-9][a-z0-9\-]{0,62}"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={add.isPending}
              required
            />
            <Input
              label="List address"
              type="url"
              className="min-w-72 flex-1"
              placeholder="https://example.com/list.txt"
              hint="An https address with no query, credentials or fragment, as plain text."
              value={url}
              onChange={(e) => setURL(e.target.value)}
              disabled={add.isPending}
              required
            />
            <Check label="Allows ranges up to /8 (cloud providers)" checked={wide} onChange={(e) => setWide(e.target.checked)} />
            <Button type="submit" variant="primary" disabled={!name.trim() || !url.trim() || add.isPending}>
              Add list
            </Button>
          </form>
        )}
        <ErrorBox error={add.error} />
        <Lookup />
      </div>
    </Card>
  );
}

// Lookup says which enabled lists hold an address.
function Lookup() {
  const [ip, setIP] = useState('');
  const [asked, setAsked] = useState('');
  const q = useQuery({
    queryKey: ['denylist-lookup', asked],
    queryFn: () => api<{ id: number; name: string; url: string; prefix: string }[]>('GET', `/api/denylists/lookup?ip=${encodeURIComponent(asked)}`),
    enabled: asked !== '',
    retry: false,
  });
  return (
    <form className="flex flex-col gap-3" onSubmit={(e) => (e.preventDefault(), ip.trim() === asked ? void q.refetch() : setAsked(ip.trim()))}>
      <div className="flex flex-wrap items-end gap-3">
        <Input label="Is this IP listed?" className="min-w-72 flex-1" placeholder="203.0.113.7" value={ip} onChange={(e) => setIP(e.target.value)} />
        <Button type="submit" disabled={!ip.trim()}>
          Check
        </Button>
      </div>
      <ErrorBox error={q.error} />
      {asked && q.data && (q.data.length === 0 ? <Notice tone="green">{asked} is on none of the lists that are on.</Notice> : <Notice tone="amber">{asked} is on {q.data.map((h) => `${h.name} (${h.prefix})`).join(', ')}.</Notice>)}
    </form>
  );
}

function Bans({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['bans'], queryFn: () => api<Ban[]>('GET', '/api/bans'), refetchInterval: 30_000 });
  const lift = useMutation({
    mutationFn: (ip: string) => api('POST', '/api/bans/lift', { ip }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['bans'] }),
  });
  const rows = q.data ?? [];
  return (
    <Card
      id="bans"
      title="Banned IPs"
      intro="Addresses a trap rule banned, newest first, as the edges last reported them. A ban shown here has not ended or been lifted, but an edge restart or removing its rule can end it without admin knowing."
      info="An IPv6 address is banned as its whole /64, shown by that range's first address. Each edge reports a ban within about a minute of recording it. At most 500 are shown."
    >
      <div className="flex flex-col gap-3">
        <ErrorBox error={q.error ?? lift.error} />
        {!q.data && !q.error && <Pending error={undefined} />}
        {q.data && rows.length === 0 && <p className="text-body">No address is banned.</p>}
        {rows.length > 0 && (
          <Table head={['IP', 'Rule', 'Tripped on', 'Since', 'Until', 'Edge', '']}>
            {rows.map((b) => (
              <tr key={`${b.edge}/${b.ip}`} className="align-top">
                <td className="font-mono">{b.ip}</td>
                <td>{b.rule}</td>
                <td className="min-w-48 break-all whitespace-normal">
                  {b.host}
                  {b.path}
                </td>
                <td title={when(b.started_at)}>{ago(b.started_at)}</td>
                <td title={when(b.ends_at)}>{when(b.ends_at)}</td>
                <td>{b.edge}</td>
                <td>
                  {b.lift_pending ? (
                    <Badge tone="amber">lifted, reaching the edges</Badge>
                  ) : (
                    canManage && (
                      <ConfirmButton
                        variant="danger"
                        title={`Lift the ban on ${b.ip}?`}
                        action="Lift ban"
                        confirm={<>The ban on {b.ip} ends on every edge within about a minute. Other rules still apply, and {b.ip} is banned again if it trips the trap.</>}
                        onConfirm={() => lift.mutate(b.ip)}
                      >
                        Lift ban
                      </ConfirmButton>
                    )
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </Card>
  );
}
