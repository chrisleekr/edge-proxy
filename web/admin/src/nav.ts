// The sidebar groups. Palette lists the same pages, so both read from here.
// Route() in App.tsx looks up a section's permission here, so every routed
// section must stay in this list.
export const nav: { group: string; links: { to: string; label: string; perm: string }[] }[] = [
  {
    group: 'Monitor',
    links: [
      { to: '/', label: 'Dashboard', perm: '' },
      { to: '/stats', label: 'Stats', perm: 'stats.read' },
      { to: '/traffic', label: 'Traffic map', perm: 'stats.read' },
      { to: '/routes', label: 'Routes', perm: 'stats.read' },
      { to: '/fleet', label: 'Fleet', perm: 'stats.read' },
      { to: '/notifications', label: 'Notifications', perm: 'stats.read' },
      { to: '/autopilot', label: 'Autopilot', perm: 'autopilot.read' },
    ],
  },
  {
    group: 'Policy',
    links: [
      { to: '/rules', label: 'Rules', perm: 'config.read' },
      { to: '/templates', label: 'Templates', perm: 'config.read' },
      { to: '/cors', label: 'CORS policies', perm: 'config.read' },
      { to: '/issuers', label: 'Issuers', perm: 'config.read' },
      { to: '/settings', label: 'Settings', perm: 'config.read' },
    ],
  },
  {
    group: 'Release',
    links: [
      { to: '/tests', label: 'Tests and simulate', perm: 'config.read' },
      { to: '/publish', label: 'Publish', perm: 'config.read' },
      { to: '/versions', label: 'Versions', perm: 'config.read' },
    ],
  },
  {
    group: 'Admin',
    links: [
      { to: '/audit', label: 'Audit log', perm: 'audit.read' },
      { to: '/users', label: 'Users and tokens', perm: 'users.manage' },
    ],
  },
];

// allowed says whether a role may open a nav section. Users also holds
// tokens, so tokens.manage alone opens it.
export const allowed = (n: { to: string; perm: string }, can: (p: string) => boolean) => !n.perm || can(n.perm) || (n.to === '/users' && can('tokens.manage'));
