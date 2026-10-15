import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type FormEvent, useState } from 'react';
import { api } from '../api';
import { Badge, Button, Card, ErrorBox, Input, Page, Table, when } from '../ui';

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
    <fieldset className="flex flex-wrap gap-3 text-sm">
      <legend className="sr-only">{label}</legend>
      {roles.data?.map((r) => (
        <label key={r.name} title={r.permissions.join(', ')}>
          <input
            type="checkbox"
            className="mr-1"
            checked={value.includes(r.name)}
            onChange={(e) => onChange(e.target.checked ? [...value, r.name] : value.filter((x) => x !== r.name))}
          />
          {r.name}
        </label>
      ))}
    </fieldset>
  );
}

const list = (s: string) =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

export function Users({ can }: { can: (p: string) => boolean }) {
  return (
    <Page title="Users and tokens">
      {can('users.manage') && <UserList />}
      {can('tokens.manage') && <Tokens />}
    </Page>
  );
}

function RoleEditor({ user }: { user: User }) {
  const qc = useQueryClient();
  const [roles, setRoles] = useState(user.roles);
  const save = useMutation({ mutationFn: () => api('PUT', `/api/users/${user.id}/roles`, { roles }), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });
  return (
    <div className="flex flex-wrap items-center gap-2">
      <RolePicker label={`Roles of ${user.username}`} value={roles} onChange={setRoles} />
      <Button disabled={roles.join() === user.roles.join() || save.isPending} onClick={() => save.mutate()}>
        Set
      </Button>
      <ErrorBox error={save.error} />
    </div>
  );
}

function UserList() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<User[]>('GET', '/api/users') });
  const disable = useMutation({ mutationFn: (id: string) => api('POST', `/api/users/${id}/disable`), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });
  const [form, setForm] = useState({ username: '', email: '', password: '', roles: ['viewer'] });
  const create = useMutation({
    mutationFn: () => api('POST', '/api/users', form),
    onSuccess: () => (setForm({ username: '', email: '', password: '', roles: ['viewer'] }), qc.invalidateQueries({ queryKey: ['users'] })),
  });
  const submit = (e: FormEvent) => (e.preventDefault(), create.mutate());
  return (
    <>
      <ErrorBox error={users.error ?? disable.error} />
      <Table head={['User', 'Email', 'Roles', 'Created', '']}>
        {users.data?.map((u) => (
          <tr key={u.id}>
            <td className="px-3 py-2">
              {u.username} {u.disabled && <Badge tone="red">disabled</Badge>}
            </td>
            <td className="px-3 py-2">{u.email}</td>
            <td className="px-3 py-2">
              <RoleEditor key={u.roles.join()} user={u} />
            </td>
            <td className="px-3 py-2">{when(u.created_at)}</td>
            <td className="px-3 py-2">
              {!u.disabled && (
                <Button variant="danger" onClick={() => confirm(`Disable ${u.username} and end their sessions?`) && disable.mutate(u.id)}>
                  Disable
                </Button>
              )}
            </td>
          </tr>
        ))}
      </Table>
      <Card title="Add a user">
        <form className="grid max-w-2xl gap-2 md:grid-cols-2" onSubmit={submit}>
          <Input label="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
          <Input label="Email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <Input label="Initial password" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-slate-700">Roles</span>
            <RolePicker label="Roles" value={form.roles} onChange={(roles) => setForm({ ...form, roles })} />
          </div>
          <div className="md:col-span-2">
            <ErrorBox error={create.error} />
            <Button type="submit" variant="primary" disabled={create.isPending}>
              Add user
            </Button>
          </div>
        </form>
      </Card>
    </>
  );
}

function Tokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => api<Token[]>('GET', '/api/tokens') });
  const revoke = useMutation({ mutationFn: (id: string) => api('DELETE', `/api/tokens/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }) });
  const [form, setForm] = useState({ name: '', kind: 'edge', scopes: '', expires_in: '' });
  const create = useMutation({
    mutationFn: () => api<{ token: string }>('POST', '/api/tokens', { ...form, scopes: list(form.scopes) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }),
  });
  const submit = (e: FormEvent) => (e.preventDefault(), create.mutate());
  return (
    <>
      <ErrorBox error={tokens.error ?? revoke.error} />
      <Table head={['Token', 'Kind', 'Scopes', 'Created', 'Expires', '']}>
        {tokens.data?.map((t) => (
          <tr key={t.id}>
            <td className="px-3 py-2">
              {t.name} {t.revoked_at && <Badge tone="red">revoked</Badge>}
            </td>
            <td className="px-3 py-2">{t.kind}</td>
            <td className="px-3 py-2">{t.scopes.join(', ')}</td>
            <td className="px-3 py-2">{when(t.created_at)}</td>
            <td className="px-3 py-2">{when(t.expires_at) || 'never'}</td>
            <td className="px-3 py-2">
              {!t.revoked_at && (
                <Button variant="danger" onClick={() => confirm(`Revoke ${t.name}?`) && revoke.mutate(t.id)}>
                  Revoke
                </Button>
              )}
            </td>
          </tr>
        ))}
      </Table>
      <Card title="Create a token">
        <form className="grid max-w-2xl gap-2 md:grid-cols-2" onSubmit={submit}>
          <Input label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-slate-700">Kind</span>
            <select className="rounded border border-slate-300 px-2 py-1.5" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="edge">edge (for edge replicas)</option>
              <option value="user">user (API access as you)</option>
            </select>
          </label>
          {form.kind === 'user' && <Input label="Scopes, comma separated" value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} />}
          <Input label="Expires in (for example 720h)" value={form.expires_in} onChange={(e) => setForm({ ...form, expires_in: e.target.value })} />
          <div className="md:col-span-2">
            <ErrorBox error={create.error} />
            <Button type="submit" variant="primary" disabled={create.isPending}>
              Create token
            </Button>
          </div>
        </form>
        {create.data && (
          <div role="status" className="mt-3 rounded border border-amber-300 bg-amber-50 p-3 text-sm">
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
          <Input label="New password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
          <p className="text-xs text-slate-500">Every session ends, including this one; sign in again afterwards.</p>
          <ErrorBox error={change.error} />
          <Button type="submit" variant="primary" disabled={change.isPending}>
            Change password
          </Button>
        </form>
      </Card>
    </Page>
  );
}
