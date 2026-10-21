import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type FormEvent, useState } from 'react';
import { api, type Me } from '../api';
import { Badge, Button, Card, Check, ConfirmButton, ErrorBox, Hint, Notice, Input, Page, Table, when } from '../ui';

interface User {
  id: string;
  username: string;
  email: string;
  disabled: boolean;
  roles: string[];
  created_at: string;
}

interface Token {
  id: string;
  name: string;
  kind: string;
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

interface Role {
  name: string;
  permissions: string[];
}

const useRoles = () => useQuery({ queryKey: ['roles'], queryFn: () => api<Role[]>('GET', '/api/roles'), staleTime: Infinity });

// RolePicker offers the roles admin knows, with what each allows.
function RolePicker({ value, onChange, label }: { value: string[]; onChange: (v: string[]) => void; label: string }) {
  const roles = useRoles();
  return (
    <fieldset className="flex flex-wrap gap-x-4 gap-y-2 text-sm text-heading">
      <legend className="sr-only">{label}</legend>
      {roles.data?.map((r) => (
        <label key={r.name} title={r.permissions.join(', ')} className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <input type="checkbox" checked={value.includes(r.name)} onChange={(e) => onChange(e.target.checked ? [...value, r.name] : value.filter((x) => x !== r.name))} />
          {r.name}
        </label>
      ))}
    </fieldset>
  );
}

// RoleGuide lists what each role allows, so picking one needs no tooltip.
function RoleGuide() {
  const roles = useRoles();
  if (!roles.data) return null;
  return (
    <details className="mt-3 rounded-control border border-line">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-heading">What each role can do</summary>
      <dl className="grid gap-x-4 gap-y-2 border-t border-line p-3 text-sm sm:grid-cols-[max-content_1fr]">
        {roles.data.map((r) => (
          <div key={r.name} className="contents">
            <dt className="font-medium">{r.name}</dt>
            <dd className="font-mono text-sm text-body">{r.permissions.join(', ')}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

// Day shows a date alone, the time on hover, so action buttons stay in view.
const Day = ({ iso }: { iso: string }) => (
  <time dateTime={iso} title={when(iso)}>
    {new Date(iso).toLocaleDateString()}
  </time>
);

export function Users({ can }: { can: (p: string) => boolean }) {
  return (
    <Page
      title="Users and tokens"
      info="Roles stack: a viewer reads, an editor also edits the draft and runs tests, a publisher also publishes and runs canaries, and an admin also manages users, tokens and settings. Menu items a role cannot use are hidden."
    >
      {can('users.manage') && <UserList />}
      {can('tokens.manage') && <Tokens />}
    </Page>
  );
}

function RoleEditor({ user, self }: { user: User; self: boolean }) {
  const qc = useQueryClient();
  const [roles, setRoles] = useState(user.roles);
  const save = useMutation({ mutationFn: () => api('PUT', `/api/users/${user.id}/roles`, { roles }), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });
  // Changing your own roles could remove the right to change them back,
  // and a disabled user's roles do nothing.
  if (self || user.disabled)
    return (
      <span className="text-body">
        {user.roles.join(', ')}
        {self && ' (another admin changes yours)'}
      </span>
    );
  return (
    <div className="flex flex-wrap items-center gap-2">
      <RolePicker label={`Roles of ${user.username}`} value={roles} onChange={setRoles} />
      {/* Shown only once the roles differ, so unchanged rows stay quiet.
          Sorted because unticking and reticking a role moves it to the end. */}
      {roles.toSorted().join() !== user.roles.toSorted().join() && (
        <Button variant="primary" disabled={save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : 'Save roles'}
        </Button>
      )}
      <ErrorBox error={save.error} />
    </div>
  );
}

function UserList() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<User[]>('GET', '/api/users') });
  const me = useQuery({ queryKey: ['me'], queryFn: () => api<Me>('GET', '/api/auth/me') });
  const disable = useMutation({ mutationFn: (id: string) => api('POST', `/api/users/${id}/disable`), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });
  const [form, setForm] = useState({ username: '', email: '', password: '', roles: ['viewer'] });
  const create = useMutation({
    mutationFn: (f: typeof form) => api('POST', '/api/users', f),
    onSuccess: () => (setForm({ username: '', email: '', password: '', roles: ['viewer'] }), qc.invalidateQueries({ queryKey: ['users'] })),
  });
  const submit = (e: FormEvent) => (e.preventDefault(), create.mutate(form));
  return (
    <>
      <h2 className="-mb-2">Users</h2>
      <ErrorBox error={users.error ?? disable.error} />
      <Table head={['User', 'Email', 'Roles', 'Created', '']} empty={users.data && 'No users.'}>
        {users.data?.map((u) => (
          <tr key={u.id} className={u.disabled ? 'text-body' : undefined}>
            <td className="whitespace-normal">
              {u.username} {u.disabled && <Badge tone="red">disabled</Badge>}
            </td>
            <td>{u.email}</td>
            <td className="min-w-56 whitespace-normal">
              <RoleEditor key={u.roles.join()} user={u} self={u.username === me.data?.username} />
            </td>
            <td>
              <Day iso={u.created_at} />
            </td>
            <td>
              {/* Disabling yourself would end this session with no way back in. */}
              {!u.disabled && u.username !== me.data?.username && (
                <ConfirmButton
                  variant="danger"
                  title={`Disable ${u.username}?`}
                  action="Disable user"
                  confirm="They are signed out everywhere and cannot sign in again. The account and its audit history stay."
                  disabled={disable.isPending}
                  onConfirm={() => disable.mutate(u.id)}
                >
                  Disable
                </ConfirmButton>
              )}
            </td>
          </tr>
        ))}
      </Table>
      <Card title="Add a user">
        <form className="grid max-w-2xl gap-2 md:grid-cols-2" onSubmit={submit}>
          <Input label="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
          <Input label="Email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <Input
            label="Initial password"
            hint="At least 15 characters, and not containing the username or edge‑proxy. A phrase of four or more words works well."
            type="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Roles</span>
            <RolePicker label="Roles" value={form.roles} onChange={(roles) => setForm({ ...form, roles })} />
          </div>
          <div className="md:col-span-2">
            <ErrorBox error={create.error} />
            {create.isSuccess && (
              <div className="mb-2">
                <Notice>Added {create.variables.username}. They can sign in with the initial password.</Notice>
              </div>
            )}
            <Button type="submit" variant="primary" disabled={create.isPending}>
              Add user
            </Button>
          </div>
        </form>
        <RoleGuide />
      </Card>
    </>
  );
}

function Tokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => api<Token[]>('GET', '/api/tokens') });
  const revoke = useMutation({ mutationFn: (id: string) => api('DELETE', `/api/tokens/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }) });
  const [form, setForm] = useState({ name: '', kind: 'edge', scopes: [] as string[], expires_in: '' });
  // A token can hold only permissions its creator has.
  const me = useQuery({ queryKey: ['me'], queryFn: () => api<Me>('GET', '/api/auth/me') });
  const create = useMutation({
    // Scopes stay in the form when the kind changes, and edge tokens refuse them.
    mutationFn: () => api<{ token: string }>('POST', '/api/tokens', form.kind === 'user' ? form : { ...form, scopes: [] }),
    // Cleared so a second Enter cannot make a duplicate token.
    onSuccess: () => (setForm({ ...form, name: '', scopes: [], expires_in: '' }), qc.invalidateQueries({ queryKey: ['tokens'] })),
  });
  const submit = (e: FormEvent) => (e.preventDefault(), create.mutate());
  return (
    <>
      <h2 className="-mb-2">API tokens</h2>
      <ErrorBox error={tokens.error ?? revoke.error} />
      <Table head={['Token', 'Kind', 'Scopes', 'Created', 'Expires', '']} empty={tokens.data && 'No tokens yet.'}>
        {tokens.data?.map((t) => (
          <tr key={t.id}>
            {/* The badge wraps under the name rather than widen the table. */}
            <td className="whitespace-normal">
              {t.name} {t.revoked_at && <Badge tone="red">revoked</Badge>}
            </td>
            <td>{t.kind}</td>
            <td>{t.scopes.join(', ')}</td>
            <td>
              <Day iso={t.created_at} />
            </td>
            <td>{t.expires_at ? <Day iso={t.expires_at} /> : 'never'}</td>
            <td>
              {!t.revoked_at && (
                <ConfirmButton
                  variant="danger"
                  title={`Revoke ${t.name}?`}
                  action="Revoke token"
                  confirm={
                    t.kind === 'edge'
                      ? 'Edges using it can no longer fetch new snapshots or report to admin. They keep serving the config they have.'
                      : 'Anything using it loses API access at once.'
                  }
                  disabled={revoke.isPending}
                  onConfirm={() => revoke.mutate(t.id)}
                >
                  Revoke
                </ConfirmButton>
              )}
            </td>
          </tr>
        ))}
      </Table>
      <Card
        title="Create a token"
        info="Edge tokens let edges fetch config and send stats. User tokens call the admin API as you, with scopes from the permissions you hold. A token is shown once, when it is created; store it then."
      >
        <form className="grid max-w-2xl gap-2 md:grid-cols-2" onSubmit={submit}>
          <Input label="Name" placeholder="such as edges-prod" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Kind</span>
            <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="edge">edge (for edge replicas)</option>
              <option value="user">user (API access as you)</option>
            </select>
          </label>
          {form.kind === 'user' && (
            <fieldset className="flex flex-col gap-1 text-sm md:col-span-2">
              <legend className="mb-1 font-medium text-heading">Scopes</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {me.data?.permissions.map((perm) => (
                  <Check
                    key={perm}
                    label={perm}
                    checked={form.scopes.includes(perm)}
                    onChange={(e) => setForm({ ...form, scopes: e.target.checked ? [...form.scopes, perm] : form.scopes.filter((x) => x !== perm) })}
                  />
                ))}
              </div>
              <span className="text-body">What the token may do, from the permissions you hold. A token with none can do nothing.</span>
            </fieldset>
          )}
          <Input
            label="Expires in"
            hint={form.kind === 'user' ? 'A duration such as 720h, at most 8760h.' : 'A duration such as 720h. Empty for never.'}
            value={form.expires_in}
            onChange={(e) => setForm({ ...form, expires_in: e.target.value })}
          />
          <div className="md:col-span-2">
            <ErrorBox error={create.error} />
            <Button type="submit" variant="primary" disabled={create.isPending}>
              Create token
            </Button>
          </div>
        </form>
        {create.data && (
          <div role="status" className="mt-3 rounded-control bg-warning-wash p-3 text-sm text-warning">
            <p className="mb-1 font-medium">Copy this token now. It is not shown again.</p>
            <code data-testid="new-token" className="break-all">
              {create.data.token}
            </code>
          </div>
        )}
      </Card>
    </>
  );
}

export function Account() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const change = useMutation({ mutationFn: () => api('POST', '/api/auth/password', { current, new: next }), onSuccess: () => window.location.assign('/') });
  return (
    <Page title="Account">
      <Card title="Change password">
        <form className="flex max-w-sm flex-col gap-2" onSubmit={(e) => (e.preventDefault(), change.mutate())}>
          <Input label="Current password" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          <Input
            label="New password"
            hint="At least 15 characters, and not containing your username or edge‑proxy."
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
          />
          <Hint>Every session ends, including this one; sign in again afterwards.</Hint>
          <ErrorBox error={change.error} />
          <Button type="submit" variant="primary" className="self-start" disabled={change.isPending}>
            Change password
          </Button>
        </form>
      </Card>
    </Page>
  );
}
