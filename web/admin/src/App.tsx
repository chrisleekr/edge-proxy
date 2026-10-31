import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type FormEvent, Fragment, lazy, type ReactNode, Suspense, useEffect, useRef, useState } from 'react';
import { api, type Me, meQuery, Problem, type Saved } from './api';
import { DraftProvider, useDraft, useOptionalDraft } from './draft';
import { phases, rulesOf } from './phases';
import { Audit } from './pages/Audit';
import { Autopilot, AutopilotCase } from './pages/Autopilot';
import { Dashboard } from './pages/Dashboard';
import { Fleet, Stats } from './pages/Fleet';
import { Memory, NoteDetail } from './pages/Memory';
import { Notifications } from './pages/Notifications';
import { RouteDetail, Routes } from './pages/Routes';
import { describe, isEmpty } from './pages/DiffView';
import { Publish, useDraftDiff, useVersions } from './pages/Publish';
import { Rules } from './pages/Rules';
import { Subject } from './pages/Subject';
import { Palette } from './Palette';
import { CORS, Issuers, Settings, Templates } from './pages/Sections';
import { Tests } from './pages/Tests';
import { Account, Users } from './pages/Users';
import { Compare, VersionDetail, Versions } from './pages/Versions';
import { Link, navigate, usePath } from './router';
import { ago, Button, CanWrite, Confirm, Crash, ErrorBox, Info, Input, Issues, Modal, NotFound, Pending, when, who, words } from './ui';

export function App() {
  const me = useQuery(meQuery);
  const expired = me.error instanceof Problem && me.error.status === 401;
  if (!me.data) {
    if (expired) return <Login />;
    return (
      <div className="p-6">
        <Pending error={me.error} />
      </div>
    );
  }
  // A session that ends mid-edit signs in over the screen, so the unsaved
  // draft and the screen's own edits survive.
  return (
    <>
      <Shell me={me.data} />
      {expired && (
        <Modal title="Session ended">
          <LoginForm username={me.data.username} />
        </Modal>
      )}
    </>
  );
}

function Login() {
  useEffect(() => {
    document.title = 'Sign in · Edge Policy Admin';
  }, []);
  return (
    <main className="grid min-h-screen place-items-center p-4">
      <div className="flex w-full max-w-sm flex-col gap-5 rounded-dialog bg-panel p-8 shadow-card">
        <div>
          <p className="eyebrow text-muted">Edge Proxy</p>
          <h1 className="mt-1">Edge Policy Admin</h1>
        </div>
        <LoginForm />
      </div>
    </main>
  );
}

function LoginForm({ username: known }: { username?: string }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState(known ?? '');
  const [password, setPassword] = useState('');
  const login = useMutation({
    mutationFn: () => api('POST', '/api/auth/login', { username, password }),
    // Everything fetched while signed out failed, so refetch it all.
    onSuccess: () => qc.invalidateQueries(),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      {known && <p className="text-body">Sign in again to keep working. Unsaved changes are kept.</p>}
      <Input label="Username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus={!known} />
      <Input
        label="Password"
        type="password"
        autoComplete="current-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
        data-autofocus={known ? true : undefined}
      />
      <ErrorBox error={login.error} />
      <Button type="submit" variant="primary" disabled={login.isPending}>
        {login.isPending ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  );
}

const nav: { group: string; links: { to: string; label: string; perm: string }[] }[] = [
  { group: 'Overview', links: [{ to: '/', label: 'Dashboard', perm: '' }] },
  {
    group: 'Policy',
    links: [
      { to: '/rules', label: 'Rules', perm: 'config.read' },
      { to: '/templates', label: 'Templates', perm: 'config.read' },
      { to: '/cors', label: 'CORS', perm: 'config.read' },
      { to: '/issuers', label: 'Issuers', perm: 'config.read' },
      { to: '/settings', label: 'Settings', perm: 'config.read' },
      { to: '/tests', label: 'Tests', perm: 'config.read' },
    ],
  },
  {
    group: 'Release',
    links: [
      { to: '/publish', label: 'Publish', perm: 'config.read' },
      { to: '/versions', label: 'Versions', perm: 'config.read' },
    ],
  },
  {
    group: 'Operate',
    links: [
      { to: '/routes', label: 'Routes', perm: 'stats.read' },
      { to: '/fleet', label: 'Fleet', perm: 'stats.read' },
      { to: '/stats', label: 'Stats', perm: 'stats.read' },
      { to: '/notifications', label: 'Notifications', perm: 'stats.read' },
      { to: '/autopilot', label: 'Autopilot', perm: 'autopilot.read' },
      { to: '/audit', label: 'Audit', perm: 'audit.read' },
    ],
  },
  { group: 'Access', links: [{ to: '/users', label: 'Users', perm: 'users.manage' }] },
];

// The rule editor brings the rule builder and its drag and drop, which only
// it uses, so they load when a rule is first opened.
const RuleEditor = lazy(() => import('./pages/RuleEditor').then((m) => ({ default: m.RuleEditor })));

// The section a path belongs to, so nested screens keep their nav link
// marked: a rule editor is under Rules, a version under Versions.
const sectionOf = (path: string) => `/${path.split('/')[1] ?? ''}`;

function Shell({ me }: { me: Me }) {
  const path = usePath();
  const can = (p: string) => me.permissions.includes(p);
  // Below lg the nav is a drawer. It remembers the path it opened on, so
  // following a link closes it.
  const [openOn, setOpenOn] = useState<string | null>(null);
  const open = openOn === path;
  const drawer = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    // Null while a lazy screen suspends the first render.
    const d = drawer.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  // Cmd+K on a Mac, Ctrl+K elsewhere, opens Find from any screen. Ctrl+K
  // on a Mac stays the text fields' delete to end of line.
  const [finding, setFinding] = useState(false);
  useEffect(() => {
    const mac = /Mac|iP(hone|ad)/.test(navigator.platform);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'k' || !(mac ? e.metaKey : e.ctrlKey)) return;
      e.preventDefault();
      setFinding(true);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  // The draft needs config.read; without it the app still serves the
  // screens the role can read, such as the dashboard and stats.
  const Draft = can('config.read') ? DraftProvider : Fragment;
  return (
    <Draft>
      <a href="#main" className="sr-only rounded-control bg-brand px-3 py-2 text-on-brand focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50">
        Skip to content
      </a>
      <div className="flex min-h-screen flex-col lg:flex-row">
        {/* From lg up the sidebar stays in view while long screens scroll.
            Below lg it would leave tables too little width, so a bar stays
            at the top and the nav opens as a drawer. */}
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-line bg-panel/95 px-3 py-2.5 backdrop-blur lg:hidden">
          <Brand />
          <Button className="inline-flex items-center gap-2" aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpenOn(path)}>
            <span aria-hidden className="flex w-3.5 flex-col gap-[3px]">
              <span className="h-px bg-current" />
              <span className="h-px bg-current" />
              <span className="h-px bg-current" />
            </span>
            Menu
          </Button>
        </header>
        <dialog
          ref={drawer}
          aria-label="Menu"
          className="drawer m-0 h-dvh max-h-none w-72 max-w-[85vw] bg-panel p-0 text-body shadow-float backdrop:bg-black/50 lg:hidden"
          onCancel={(e) => (e.preventDefault(), setOpenOn(null))}
          // A click on the backdrop lands on the dialog itself.
          onClick={(e) => e.target === e.currentTarget && setOpenOn(null)}
        >
          <div className="flex h-full flex-col gap-6 overflow-y-auto p-4">
            <div className="flex items-center justify-between gap-3">
              <Brand />
              <Button onClick={() => setOpenOn(null)}>Close</Button>
            </div>
            <NavLinks path={path} can={can} />
            <UserBar me={me} path={path} />
          </div>
        </dialog>
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col gap-6 overflow-y-auto border-r border-line bg-panel p-4 lg:flex">
          <Brand />
          <NavLinks path={path} can={can} />
          <UserBar me={me} path={path} />
        </aside>
        <main id="main" tabIndex={-1} className="flex min-w-0 flex-1 flex-col gap-5 p-4 focus:outline-none lg:p-8">
          {can('config.read') && <Track />}
          {/* Keyed by path so a save notice clears on the next screen. */}
          {can('config.read') && <SaveBar key={`save ${path}`} path={path} canWrite={can('config.write')} />}
          <Crash key={path}>
            <Suspense fallback={<Pending error={null} />}>
              <CanWrite.Provider value={can('config.write')}>
                <Route path={path} can={can} />
              </CanWrite.Provider>
            </Suspense>
          </Crash>
        </main>
      </div>
      {finding && <Palette onClose={() => setFinding(false)} />}
    </Draft>
  );
}

function Brand() {
  return (
    <Link to="/" className="flex flex-col px-2 leading-tight">
      <span className="eyebrow text-muted">Edge Proxy</span>
      <span className="text-base font-semibold tracking-tight whitespace-nowrap text-heading">Policy Admin</span>
    </Link>
  );
}

// allowed says whether a role may open a nav section. Users also holds
// tokens, so tokens.manage alone opens it.
const allowed = (n: { to: string; perm: string }, can: (p: string) => boolean) => !n.perm || can(n.perm) || (n.to === '/users' && can('tokens.manage'));

// NavLinks is the grouped nav, shared by the sidebar and the drawer.
function NavLinks({ path, can }: { path: string; can: (p: string) => boolean }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-5">
      {nav.map(({ group, links }) => {
        const shown = links.filter((n) => allowed(n, can));
        if (shown.length === 0) return null;
        return (
          <div key={group} className="flex flex-col gap-0.5">
            <p className="eyebrow mb-1 px-2 text-muted">{group}</p>
            {shown.map((n) => (
              <Link
                key={n.to}
                to={n.to}
                current={sectionOf(path) === n.to}
                className="rounded-control px-2 py-2 text-sm font-medium text-body hover:bg-soft hover:text-heading aria-[current]:bg-soft aria-[current]:text-heading lg:py-1.5"
              >
                {n.label}
              </Link>
            ))}
          </div>
        );
      })}
    </nav>
  );
}

function UserBar({ me, path }: { me: Me; path: string }) {
  return (
    <div className="mt-auto flex items-center justify-between gap-2 border-t border-line pt-4 text-sm">
      <Link to="/account" current={path === '/account'} className="rounded-control px-2 py-1 font-medium text-body hover:bg-soft hover:text-heading aria-[current]:bg-soft aria-[current]:text-heading">
        {me.username}
      </Link>
      <SignOut />
    </div>
  );
}

// A hand-typed address like /subjects/% is not valid percent-encoding, and
// decodeURIComponent would throw; the raw segment then finds nothing.
function decodePart(part = '') {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

function Route({ path, can }: { path: string; can: (p: string) => boolean }) {
  const parts = path.split('/').filter(Boolean);
  const routes: Record<string, () => ReactNode> = {
    '': () => <Dashboard can={can} />,
    // Keyed by path so moving between rules (back, forward) resets the form.
    rules: () => (parts[1] ? <RuleEditor key={path} phase={parts[1]} id={decodePart(parts[2])} /> : <Rules />),
    templates: () => <Templates />,
    cors: () => <CORS />,
    issuers: () => <Issuers />,
    settings: () => <Settings canManage={can('settings.manage')} />,
    tests: () => <Tests canTest={can('config.test')} canWrite={can('config.write')} />,
    publish: () => <Publish can={can} />,
    versions: () => (parts[1] === 'compare' ? <Compare /> : parts[1] ? <VersionDetail version={Number(parts[1])} can={can} /> : <Versions can={can} />),
    routes: () => (parts[1] ? <RouteDetail key={path} id={Number(parts[1])} can={can} /> : <Routes can={can} />),
    fleet: () => <Fleet />,
    stats: () => <Stats />,
    notifications: () => <Notifications canManage={can('settings.manage')} />,
    autopilot: () =>
      parts[1] === 'cases' && parts[2] ? (
        <AutopilotCase key={path} id={Number(parts[2])} />
      ) : parts[1] === 'notes' ? (
        parts[2] ? (
          <NoteDetail key={path} id={Number(parts[2])} />
        ) : (
          <Memory />
        )
      ) : parts[1] ? (
        <NotFound />
      ) : (
        <Autopilot />
      ),
    audit: () => <Audit />,
    users: () => <Users can={can} />,
    account: () => <Account />,
    subjects: () => <Subject key={path} display={decodePart(parts[1])} />,
  };
  const r = routes[parts[0] ?? ''];
  // A typed or bookmarked address can reach a section the nav hides. A
  // client's page is reached from Stats, so it needs what Stats needs.
  const section = parts[0] === 'subjects' ? { to: '/subjects', perm: 'stats.read' } : nav.flatMap((g) => g.links).find((n) => n.to === sectionOf(path));
  if (r && section && !allowed(section, can)) return <NotFound title="No access">Your role cannot open this page.</NotFound>;
  return r ? r() : <NotFound />;
}

function SignOut() {
  const qc = useQueryClient();
  // Null for a role without config.read, which has no draft.
  const d = useOptionalDraft();
  const [error, setError] = useState<unknown>();
  const logout = async () => {
    if (d?.dirty && !confirm('Sign out and lose your unsaved changes to the draft?')) return;
    // A failed sign out leaves the session open, so the user must see it.
    try {
      await api('POST', '/api/auth/logout');
    } catch (e) {
      return setError(e);
    }
    navigate('/', { force: true });
    // Reset, not clear: App watches the me query, and a reset query loses
    // its data and refetches, so App sees the 401 and shows sign in.
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' });
    await qc.resetQueries({ queryKey: ['me'] });
  };
  return (
    <>
      <ErrorBox error={error} />
      <button type="button" className="rounded-control px-3 py-1 font-medium whitespace-nowrap text-heading shadow-field hover:bg-soft" onClick={() => void logout()}>
        Sign out
      </button>
    </>
  );
}

// Track shows where policy stands on every screen: the shared draft, a
// canary if one runs, and the live version, in the order a change travels.
function Track() {
  const d = useDraft();
  const versions = useVersions();
  const live = versions.data?.find((v) => v.status === 'active');
  const canary = versions.data?.find((v) => v.status === 'canary');
  const pct = useQuery({
    queryKey: ['canary'],
    queryFn: () => api<{ canary: { percent: number } | null }>('GET', '/api/canary'),
    enabled: !!canary,
    refetchInterval: 30_000,
  });
  const { against, diff } = useDraftDiff();
  const behind = !!live && d.draft.base_version !== live.version && d.draft.base_version !== canary?.version;
  const [draft, tone] = d.dirty
    ? ['Unsaved edits', 'text-warning']
    : d.draft.revision === 0
      ? ['Nothing saved yet', 'text-body']
      : behind
        ? [`${d.draft.base_version === null ? 'Not based' : `Based on v${d.draft.base_version}, not`} on live v${live.version}: rebase on Publish`, 'text-warning']
        : !diff.data || !against
          ? // Until the comparison loads, so the label does not flip.
            versions.isLoading || diff.isLoading
            ? ['…', 'text-body']
            : [`Saved, revision ${d.draft.revision}`, 'text-heading']
          : isEmpty(diff.data.diff)
            ? [`Same as ${against.status === 'canary' ? 'canary' : 'live'}`, 'text-body']
            : [`Not published: ${describe(diff.data.diff).toLowerCase()}`, 'text-warning'];
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-card bg-panel px-4 py-2.5 text-sm shadow-card">
      <Station to="/publish" name="Draft" title={d.draft.revision ? `Saved by ${who(d.draft.updated_by)} at ${when(d.draft.updated_at)}` : undefined}>
        <span className={tone}>{draft}</span>
      </Station>
      {canary && (
        <>
          <Arrow />
          <Station to="/publish" name="Canary">
            <span className="text-heading">
              v{canary.version}
              {pct.data?.canary && ` on ${pct.data.canary.percent}%`}
            </span>
          </Station>
        </>
      )}
      <Arrow />
      <Station to={live ? `/versions/${live.version}` : '/versions'} name="Live" title={live ? `Published ${when(live.published_at)}` : undefined}>
        {live ? (
          <span className="flex items-center gap-1.5 text-heading">
            <span aria-hidden className="size-2 rounded-full bg-success" />v{live.version}
            <span className="text-body">
              by {who(live.author)}, {ago(live.published_at)}
            </span>
          </span>
        ) : (
          <span className="text-body">{versions.data ? 'Nothing published yet' : '…'}</span>
        )}
      </Station>
      <span className="ml-auto">
        <Info label="draft, canary and live">
          Everyone edits one shared draft. Saving checks it with the same validator the edges run, so nothing invalid is saved. Publish makes the saved draft a new
          numbered version, on all traffic or first as a canary on part of it. Edges pick up a new version within about 5 seconds.
        </Info>
      </span>
    </div>
  );
}

function Station({ to, name, title, children }: { to: string; name: string; title?: string | undefined; children: ReactNode }) {
  return (
    <span title={title}>
      <Link to={to} className="-mx-1.5 flex items-baseline gap-2 rounded-control px-1.5 py-0.5 hover:bg-soft">
        <span className="eyebrow text-muted">{name}</span>
        {children}
      </Link>
    </span>
  );
}

// Hidden on phones, where the stations wrap onto their own lines.
const Arrow = () => (
  <span aria-hidden className="text-muted max-sm:hidden">
    →
  </span>
);

// SaveBar saves or discards the draft edits made on any screen.
const checking = 'Checking your changes…';
function SaveBar({ path, canWrite }: { path: string; canWrite: boolean }) {
  const d = useDraft();
  const save = useMutation<Saved>({ mutationFn: d.save });
  const [discarding, setDiscarding] = useState(false);
  const blocked = !canWrite
    ? 'Your role cannot save the draft.'
    : d.stale
      ? 'Discard, then redo your changes on their version.'
      : d.invalid.length > 0
        ? `Fix the JSON in ${d.invalid.join(', ')} to save.`
        : !d.check
          ? checking
          : d.check.failed
            ? `Could not check your changes: ${d.check.failed}. Save is off until they can be checked.`
            : d.check.checked?.errors.length
              ? `Fix ${d.check.checked.errors.length === 1 ? 'the problem' : `the ${d.check.checked.errors.length} problems`} to save.`
              : undefined;
  // A fresh install's starter draft is valid but has never been saved, and
  // publish needs a saved draft, so the bar offers to save it unchanged.
  const unsaved = !d.dirty && d.draft.revision === 0 && canWrite;
  const ready = (d.dirty || unsaved) && !blocked && !save.isPending;
  const { mutate } = save;
  // Cmd or Ctrl+S saves the draft from any screen, as in an editor.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 's' || !(e.metaKey || e.ctrlKey)) return;
      e.preventDefault();
      if (ready) mutate();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [ready, mutate]);
  // An issue in a rule names it by position, such as
  // config.rate_limit_rules[3].id; this finds that rule's editor. Other
  // issues go to the page that edits their section.
  const ruleLink = (path: string) => {
    const m = /^config\.(\w+_rules)\[(\d+)\]/.exec(path);
    const p = m && phases.find((x) => x.key === m[1]);
    const r = p && rulesOf(d.config, p.key)[Number(m[2])];
    if (r) return `/rules/${p.phase}/${encodeURIComponent(r.id)}`;
    if (/^config\.global\.(responses|defaults\.responses)\b/.test(path)) return '/templates';
    if (path.startsWith('config.global.cors_policies')) return '/cors';
    if (path.startsWith('config.auth')) return '/issuers';
    if (/^config\.(global|kill_switch)\b/.test(path)) return '/settings';
    return undefined;
  };
  // No link to the page already open.
  const link = (p: string) => (ruleLink(p) === path ? undefined : ruleLink(p));
  // where names an issue's place for people: "rule login-per-ip, limit"
  // rather than config.rate_limit_rules[0].limit.
  const where = (p: string) => {
    // Fields named on screen differently from their config key.
    const label: Record<string, string> = { jwks_url: 'keys URL', algorithm: 'signing algorithm' };
    const rest = (r: string) => (r ? `, ${words(r.replace(/^\./, '').replace(/^\w+$/, (k) => label[k] ?? k)).replaceAll(' › ', ' ')}` : '');
    p = p.replace(/^(?!config\.)/, 'config.');
    const m = /^config\.(\w+_rules)\[(\d+)\](.*)$/.exec(p);
    const rule = m && rulesOf(d.config, phases.find((x) => x.key === m[1])?.key ?? 'config_rules')[Number(m[2])];
    if (m && rule) return `rule ${rule.id}${rest(m[3]!)}`;
    const i = /^config\.auth\.issuers\[(\d+)\](.*)$/.exec(p);
    if (i) {
      // Named by ID as on the Issuers page, by position until it has one.
      const is = d.config.auth.issuers?.[Number(i[1])] as { id?: unknown } | undefined;
      return `issuer ${typeof is?.id === 'string' && is.id ? is.id : Number(i[1]) + 1}${rest(i[2]!)}`;
    }
    const t = /^config\.global\.(responses|cors_policies)\["([^"]+)"\](.*)$/.exec(p);
    if (t) return `${t[1] === 'responses' ? 'template' : 'CORS policy'} ${t[2]}${rest(t[3]!)}`;
    return words(p);
  };
  if (!d.dirty && !unsaved && !save.data && !save.error) return null;
  // Below lg the top bar (about 61px) is sticky too and sits above this one,
  // so the bar sticks under it or the top bar would cover Save draft.
  return (
    <div className="sticky top-18 z-10 flex flex-col gap-2 rounded-card bg-panel p-3 shadow-float lg:top-2">
      {(d.dirty || unsaved) && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-full bg-brand px-2.5 py-0.5 text-xs font-medium text-on-brand">Draft</span>
          <div className="mr-auto flex flex-col">
            <span className="text-sm text-heading">
              {d.stale
                ? `${who(d.draft.updated_by)} saved the draft at ${when(d.draft.updated_at)}, after you started editing.`
                : unsaved
                  ? 'The starter draft is not saved yet. Save it to publish it.'
                  : 'Unsaved changes to the draft.'}
            </span>
            {blocked && <span className={`text-sm ${blocked === checking ? 'text-body' : 'text-danger'}`}>{blocked}</span>}
          </div>
          <Button variant="primary" disabled={!ready} onClick={() => save.mutate()} title="Cmd or Ctrl+S">
            {save.isPending ? 'Saving…' : 'Save draft'}
          </Button>
          {d.dirty && <Button onClick={() => setDiscarding(true)}>Discard</Button>}
          {discarding && (
            <Confirm title="Discard changes?" action="Discard changes" variant="danger" onConfirm={() => (d.discard(), save.reset())} onClose={() => setDiscarding(false)}>
              Every unsaved change on every screen goes back to the saved draft.
            </Confirm>
          )}
        </div>
      )}
      {/* The rule editor lists its own rule's problems, so the bar leaves those
          out there. Other screens may not show every problem (JSON mode, a whole
          list), so the bar lists them all. */}
      {d.dirty && <Issues issues={d.check?.checked?.errors.filter((i) => !(path.startsWith('/rules/') && ruleLink(i.path) === path))} link={link} where={where} />}
      {/* The stale line above already explains a save someone else beat. */}
      {!d.stale && <ErrorBox error={save.error} link={link} />}
      {save.data && !d.dirty && (
        <div className="flex flex-col gap-2 text-sm">
          <p role="status">
            Saved revision {save.data.revision}.{' '}
            {!!save.data.test_results?.length && `${save.data.test_results.filter((t) => t.pass).length} of ${save.data.test_results.length} tests pass. `}
            Edges still serve the live version until you{' '}
            <Link to="/publish" className="underline">
              publish
            </Link>
            .
          </p>
          <Issues issues={save.data.warnings} tone="amber" link={link} where={where} />
        </div>
      )}
    </div>
  );
}
