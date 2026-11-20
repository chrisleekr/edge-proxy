import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, Problem } from '../api';
import { Errors } from '../RuleForms';
import { Badge, Button, Card, Check, ConfirmButton, ErrorBox, Input, Notice, Page, Pending, Table, ago, plural, when } from '../ui';

// The IP lists page: lists typed in admin or downloaded for client.ip_lists, and the
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
  // Where rules name this list, such as "rule cfg-office (the active version)".
  used_by: string[];
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

export const ipListsQuery = { queryKey: ['ip-lists'], queryFn: () => api<Source[]>('GET', '/api/ip-lists'), refetchInterval: 60_000 };

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
  const q = useQuery(ipListsQuery);
  const [name, setName] = useState('');
  const [typed, setTyped] = useState(true);
  const [text, setText] = useState('');
  const [url, setURL] = useState('');
  const [wide, setWide] = useState(false);
  const [editing, setEditing] = useState<number>();
  const refresh = () => qc.invalidateQueries({ queryKey: ipListsQuery.queryKey });
  const add = useMutation({
    mutationFn: () => api('POST', '/api/ip-lists', typed ? { name: name.trim(), entries: text, wide } : { name: name.trim(), url: url.trim(), wide }),
    onSuccess: () => (setName(''), setText(''), setURL(''), setWide(false), void refresh()),
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
      intro={'Rules match a list by its name, such as client.ip_lists in {"aws"}, to block or to always allow. Only lists that are on are matched. A list you type is kept as written; a list from a URL is downloaded about once an hour and the last good copy is kept. A change reaches every edge within about a minute, without a publish.'}
      info="A list is one address or range per line. A typed list refuses any line it cannot use, and names the line. In a downloaded list, a file that starts with { or [ is read as JSON and every address or range among its values counts; otherwise text after a space, a tab, a comma, a semicolon or a hash is ignored and unusable lines are skipped. Ranges wider than a /16 for IPv4 or a /32 for IPv6 are refused or skipped, or wider than a /8 and a /16 on a list that allows wide ranges. Entry counts are exact: they count the ranges kept, after repeats are removed. A failed download changes nothing on the edges: they keep the last good list. At most 128 lists, and edges take at most 500,000 entries in all. Typed lists are taken first, then the others in the order they were added, and one that would pass that is left out whole."
    >
      <div className="flex flex-col gap-4">
        <ErrorBox error={q.error ?? change.error} />
        {!q.data && !q.error && <Pending error={undefined} />}
        {q.data && rows.length === 0 && <p className="text-body">No lists. Rules that read client.ip_lists match no one until one is added.</p>}
        {rows.length > 0 && (
          <Table head={['Name', 'Source', 'State', 'Entries', 'Updated', '']} num={[3]}>
            {rows.flatMap((s) => {
              const st = stateOf(s);
              const isTyped = s.url === '';
              const row = (
                <tr key={s.id} className="align-top">
                  {/* Most lists are used by no rule, so the rules sit under the name instead of in a mostly empty column. */}
                  <td className="min-w-40 whitespace-normal">
                    <span className="font-mono">{s.name}</span>
                    {s.used_by.length > 0 && <p className="text-body">Used by {s.used_by.join(', ')}</p>}
                  </td>
                  <td className="min-w-56 whitespace-normal">
                    {/* Only the URL may break anywhere; the notes under it wrap at words. */}
                    {isTyped ? <span className="font-sans">Typed in admin</span> : <span className="font-mono break-all">{s.url}</span>}
                    {s.wide && <p className="font-sans text-body">Allows ranges up to /8.</p>}
                    {s.failures > 0 && s.last_error && <p className="font-sans break-words text-body">Last error: {s.last_error}</p>}
                    {s.skipped > 0 && <p className="font-sans text-body">{plural(s.skipped, 'line')} of the last download could not be used and were skipped.</p>}
                  </td>
                  <td>
                    <Badge tone={st.tone}>{st.words}</Badge>
                  </td>
                  <td className="text-right tabular-nums">{s.entries === 0 ? 'none' : s.entries.toLocaleString()}</td>
                  <td>{s.fetched_at ? <span title={when(s.fetched_at)}>{ago(s.fetched_at)}</span> : 'never'}</td>
                  {/* Two buttons a row keep each list's row short. */}
                  <td className="min-w-52">
                    {canManage && (
                      <div className="flex flex-wrap gap-2">
                        <Button disabled={change.isPending} onClick={() => setEditing(editing === s.id ? undefined : s.id)}>
                          Edit
                        </Button>
                        {!isTyped && (
                          <Button disabled={change.isPending || !s.enabled} onClick={() => change.mutate({ method: 'POST', path: `/api/ip-lists/${s.id}/refresh` })}>
                            Refresh now
                          </Button>
                        )}
                        <Button disabled={change.isPending} onClick={() => change.mutate({ method: 'PATCH', path: `/api/ip-lists/${s.id}`, body: { enabled: !s.enabled } })}>
                          {s.enabled ? 'Turn off' : 'Turn on'}
                        </Button>
                        <ConfirmButton
                          variant="danger"
                          title="Remove this list?"
                          action="Remove"
                          confirm={
                            <>
                              Edges drop {s.name} from <code>client.ip_lists</code> within about a minute, without a publish: a rule that requires it matches no one, and an exclusion that names it excludes no one.
                              {s.used_by.length > 0 && <> These rules will stop matching: {s.used_by.join(', ')}.</>}
                            </>
                          }
                          onConfirm={() => change.mutate({ method: 'DELETE', path: `/api/ip-lists/${s.id}` })}
                        >
                          Remove
                        </ConfirmButton>
                      </div>
                    )}
                  </td>
                </tr>
              );
              return editing === s.id && canManage
                ? [
                    row,
                    <tr key={`${s.id}-edit`}>
                      <td colSpan={6} className="whitespace-normal">
                        <EditList s={s} onDone={() => (setEditing(undefined), void refresh())} />
                      </td>
                    </tr>,
                  ]
                : [row];
            })}
          </Table>
        )}
        {canManage && (
          <form className="flex flex-col gap-3" onSubmit={(e) => (e.preventDefault(), add.mutate())}>
            <h3 className="font-medium text-heading">Add a list</h3>
            <Input
              label="Name"
              className="max-w-sm"
              placeholder="office"
              hint="What rules write. Lowercase letters, digits and hyphens. It can change only while no rule uses it."
              pattern="[a-z0-9][a-z0-9\-]{0,62}"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={add.isPending}
              required
            />
            <fieldset className="flex flex-col gap-1 text-sm">
              <legend className="font-medium text-heading">Where do the addresses come from?</legend>
              <label className="inline-flex items-center gap-2">
                <input type="radio" name="source" checked={typed} onChange={() => setTyped(true)} />
                I'll type them
              </label>
              <label className="inline-flex items-center gap-2">
                <input type="radio" name="source" checked={!typed} onChange={() => setTyped(false)} />
                Download from a URL
              </label>
            </fieldset>
            {typed ? (
              <label className="flex flex-col gap-1 text-sm">
                <span className="font-medium text-heading">Addresses, one per line</span>
                <textarea className="w-full max-w-2xl font-mono" rows={4} placeholder={'203.0.113.10\n198.51.100.0/24'} value={text} onChange={(e) => setText(e.target.value)} disabled={add.isPending} />
              </label>
            ) : (
              <Input
                label="List address"
                type="url"
                className="min-w-72 max-w-2xl"
                placeholder="https://example.com/list.txt"
                hint="An https address with no query, credentials or fragment, serving plain text or JSON."
                value={url}
                onChange={(e) => setURL(e.target.value)}
                disabled={add.isPending}
                required
              />
            )}
            <div className="flex flex-wrap items-center gap-3">
              <Check label="Allows ranges up to /8 (cloud providers)" checked={wide} onChange={(e) => setWide(e.target.checked)} disabled={add.isPending} />
              <Button type="submit" variant="primary" disabled={!name.trim() || !(typed ? text.trim() : url.trim()) || add.isPending}>
                Add list
              </Button>
            </div>
            <LineIssues error={add.error} />
          </form>
        )}
        <Lookup />
      </div>
    </Card>
  );
}

// LineIssues shows a rejected list under its form: the server names each bad
// line, and any other failure shows as is.
function LineIssues({ error }: { error: unknown }) {
  if (error instanceof Problem && error.status === 422 && error.errors.length > 0) return <Errors issues={error.errors} />;
  return <ErrorBox error={error} />;
}

// EditList changes one list. It sends only what changed, so an unchanged
// name is never checked against the rules that use it.
function EditList({ s, onDone }: { s: Source; onDone: () => void }) {
  const typed = s.url === '';
  const entries = useQuery({ queryKey: ['ip-list-entries', s.id], queryFn: () => api<{ entries: string }>('GET', `/api/ip-lists/${s.id}/entries`), enabled: typed });
  const [name, setName] = useState(s.name);
  const [url, setURL] = useState(s.url);
  const [wide, setWide] = useState(s.wide);
  const [text, setText] = useState<string>();
  const body = text ?? entries.data?.entries ?? '';
  const locked = s.used_by.length > 0;
  const patch = {
    ...(name !== s.name && { name: name.trim() }),
    ...(!typed && url !== s.url && { url: url.trim() }),
    ...(wide !== s.wide && { wide }),
    ...(typed && text !== undefined && text !== entries.data?.entries && { entries: text }),
  };
  const save = useMutation({ mutationFn: () => api('PATCH', `/api/ip-lists/${s.id}`, patch), onSuccess: onDone });
  const changed = Object.keys(patch).length > 0;
  const count = body.split('\n').filter((l) => l.trim()).length;
  return (
    <form className="flex flex-col gap-3 py-2" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
      <Input
        label="Name"
        className="max-w-sm"
        value={name}
        onChange={(e) => setName(e.target.value)}
        disabled={locked || save.isPending}
        hint={locked ? `Can't be renamed while rules use it: ${s.used_by.join(', ')}. Change those rules first.` : 'Lowercase letters, digits and hyphens.'}
      />
      {typed ? (
        <div className="flex flex-col gap-1 text-sm">
          {/* As wide as the box, so the count sits at its right edge. */}
          <label className="flex max-w-2xl flex-col gap-1">
            <span className="flex flex-wrap justify-between gap-2">
              <span className="font-medium text-heading">Addresses, one per line</span>
              <span className="text-body">{count.toLocaleString()} of 10,000</span>
            </span>
            <textarea className="w-full max-w-2xl font-mono" rows={Math.min(12, Math.max(4, count + 1))} value={body} onChange={(e) => setText(e.target.value)} disabled={!entries.data || save.isPending} />
          </label>
          <ErrorBox error={entries.error} />
          <LineIssues error={save.error} />
        </div>
      ) : (
        <>
          <Input label="List address" type="url" className="max-w-2xl" value={url} onChange={(e) => setURL(e.target.value)} disabled={save.isPending} hint="An https address with no query, credentials or fragment, serving plain text or JSON." />
          <LineIssues error={save.error} />
        </>
      )}
      <Check label="Allows ranges up to /8 (cloud providers)" checked={wide} onChange={(e) => setWide(e.target.checked)} disabled={save.isPending} />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={!changed || save.isPending || (typed && !entries.data)}>
          Save
        </Button>
        <Button onClick={onDone}>Cancel</Button>
      </div>
      <p className="text-sm text-body">Saved changes reach every edge within about a minute, no publish.</p>
    </form>
  );
}

// Lookup says which enabled lists hold an address.
function Lookup() {
  const [ip, setIP] = useState('');
  const [asked, setAsked] = useState('');
  const q = useQuery({
    queryKey: ['ip-list-lookup', asked],
    queryFn: () => api<{ id: number; name: string; url: string; prefix: string }[]>('GET', `/api/ip-lists/lookup?ip=${encodeURIComponent(asked)}`),
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
      intro="Addresses a trap rule banned, newest first, as the edges last reported them. A reported ban that has not ended or been lifted is listed; an edge restart ends one, and removing its rule suspends it, without admin knowing. A ban lifted in the last 5 minutes is also listed, marked as still reaching the edges."
      info="An IPv6 address is banned as its whole /64, shown by that range's first address. Each edge reports a ban within about a minute of recording it. At most 500 are shown."
    >
      <div className="flex flex-col gap-3">
        <ErrorBox error={q.error ?? lift.error} />
        {!q.data && !q.error && <Pending error={undefined} />}
        {q.data && rows.length === 0 && <p className="text-body">No address is banned.</p>}
        {rows.length > 0 && (
          <Table head={['IP', 'Rule', 'Tripped on', 'Last tripped', 'Until', 'Edge', '']}>
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
