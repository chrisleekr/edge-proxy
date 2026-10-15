import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type FormEvent, type ReactNode, useState } from 'react';
import { api, type Me, Problem, type Saved } from './api';
import { DraftProvider, useDraft } from './draft';
import { Audit } from './pages/Audit';
import { Fleet, Stats } from './pages/Fleet';
import { Publish } from './pages/Publish';
import { RuleEditor } from './pages/RuleEditor';
import { Rules } from './pages/Rules';
import { CORS, Issuers, Settings, Templates } from './pages/Sections';
import { Tests } from './pages/Tests';
import { Account, Users } from './pages/Users';
import { Compare, VersionDetail, Versions } from './pages/Versions';
import { Link, navigate, usePath } from './router';
import { Button, ErrorBox, Input, Issues } from './ui';

export function App() {
  const me = useQuery({ queryKey: ['me'], queryFn: () => api<Me>('GET', '/api/auth/me'), retry: false });
  if (me.isPending) return <p className="p-6">Loading…</p>;
  if (me.error instanceof Problem && me.error.status === 401) return <Login />;
  if (me.error) return <ErrorBox error={me.error} />;
  return <Shell me={me.data} />;
}

function Login() {
  const qc = useQueryClient();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const login = useMutation({
    mutationFn: () => api('POST', '/api/auth/login', { username, password }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };
  return (
    <main className="mx-auto mt-24 max-w-sm px-4">
      <form onSubmit={submit} className="flex flex-col gap-3 rounded border border-slate-200 bg-white p-6">
        <h1 className="text-lg font-semibold">Edge Policy Admin</h1>
        <Input label="Username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <Input label="Password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <ErrorBox error={login.error} />
        <Button type="submit" variant="primary" disabled={login.isPending}>
          Sign in
        </Button>
      </form>
    </main>
  );
}

const nav: { to: string; label: string; perm: string }[] = [
  { to: '/', label: 'Rules', perm: 'config.read' },
  { to: '/templates', label: 'Templates', perm: 'config.read' },
  { to: '/cors', label: 'CORS', perm: 'config.read' },
  { to: '/issuers', label: 'Issuers', perm: 'config.read' },
  { to: '/settings', label: 'Settings', perm: 'config.read' },
  { to: '/tests', label: 'Tests', perm: 'config.read' },
  { to: '/publish', label: 'Publish', perm: 'config.read' },
  { to: '/versions', label: 'Versions', perm: 'config.read' },
  { to: '/fleet', label: 'Fleet', perm: 'stats.read' },
  { to: '/stats', label: 'Stats', perm: 'stats.read' },
  { to: '/audit', label: 'Audit', perm: 'audit.read' },
  { to: '/users', label: 'Users', perm: 'users.manage' },
];

function Shell({ me }: { me: Me }) {
  const qc = useQueryClient();
  const path = usePath();
  const can = (p: string) => me.permissions.includes(p);
  const logout = async () => {
    await api('POST', '/api/auth/logout');
    qc.clear();
    navigate('/');
    await qc.invalidateQueries({ queryKey: ['me'] });
  };
  return (
    <DraftProvider>
      <div className="flex min-h-screen flex-col md:flex-row">
        <nav aria-label="Main" className="flex flex-col gap-1 border-b border-slate-200 bg-white p-3 md:w-48 md:border-r md:border-b-0">
          <p className="mb-2 font-semibold">Edge Policy</p>
          <div className="flex flex-wrap gap-1 md:flex-col">
            {nav
              .filter((n) => can(n.perm) || (n.to === '/users' && can('tokens.manage')))
              .map((n) => (
                <Link key={n.to} to={n.to} className="rounded px-2 py-1 text-sm hover:bg-slate-100 aria-[current=page]:bg-slate-900 aria-[current=page]:text-white">
                  {n.label}
                </Link>
              ))}
          </div>
          <div className="mt-auto pt-4 text-sm text-slate-600">
            <Link to="/account" className="underline">
              {me.username}
            </Link>
            <button type="button" className="ml-3 underline" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </nav>
        <main className="flex min-w-0 flex-1 flex-col gap-4 p-4 md:p-6">
          {/* Keyed by path so a save notice clears on the next screen. */}
          <SaveBar key={path} canWrite={can('config.write')} />
          <Route path={path} can={can} />
        </main>
      </div>
    </DraftProvider>
  );
}

function Route({ path, can }: { path: string; can: (p: string) => boolean }) {
  const parts = path.split('/').filter(Boolean);
  const routes: Record<string, () => ReactNode> = {
    '': () => <Rules />,
    // Keyed by path so moving between rules (back, forward) resets the form.
    rules: () => <RuleEditor key={path} phase={parts[1] ?? ''} id={decodeURIComponent(parts[2] ?? '')} />,
    templates: () => <Templates />,
    cors: () => <CORS />,
    issuers: () => <Issuers />,
    settings: () => <Settings canManage={can('settings.manage')} />,
    tests: () => <Tests canTest={can('config.test')} />,
    publish: () => <Publish can={can} />,
    versions: () => (parts[1] === 'compare' ? <Compare /> : parts[1] ? <VersionDetail version={Number(parts[1])} can={can} /> : <Versions can={can} />),
    fleet: () => <Fleet />,
    stats: () => <Stats />,
    audit: () => <Audit />,
    users: () => <Users can={can} />,
    account: () => <Account />,
  };
  const r = routes[parts[0] ?? ''];
  return r ? r() : <p>Not found.</p>;
}

// SaveBar saves or discards the draft edits made on any screen.
function SaveBar({ canWrite }: { canWrite: boolean }) {
  const d = useDraft();
  const save = useMutation<Saved>({ mutationFn: d.save });
  if (!d.dirty && !save.data && !save.error) return null;
  return (
    <div className="sticky top-0 z-10 flex flex-col gap-2 rounded border border-slate-300 bg-amber-50 p-3">
      {d.dirty && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm">{d.stale ? 'Someone saved the draft after you started editing. Saving will fail; discard and redo your changes.' : 'Unsaved changes to the draft.'}</span>
          <Button variant="primary" disabled={!canWrite || d.invalid || save.isPending} onClick={() => save.mutate()}>
            Save draft
          </Button>
          <Button onClick={() => (d.discard(), save.reset())}>Discard</Button>
        </div>
      )}
      <ErrorBox error={save.error} />
      {save.data && !d.dirty && (
        <div className="flex flex-col gap-2 text-sm">
          <p role="status">
            Saved revision {save.data.revision}.{' '}
            {!!save.data.test_results?.length && `${save.data.test_results.filter((t) => t.pass).length} of ${save.data.test_results.length} tests pass.`}
          </p>
          <Issues issues={save.data.warnings} tone="amber" />
        </div>
      )}
    </div>
  );
}
