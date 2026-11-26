# Admin UI tour

Every page of the admin UI, with what it is for and what it does, grouped as in its menu. The screenshots come from the [demo](../get-started.md) data and are regenerated from the UI, so they match the current release.

- [Monitor](monitor.md): Dashboard, Stats, the client page, War room, Routes, Fleet, Notifications, Autopilot and its memory.
- [Policy](../use/policy.md): Rules and the rule editor, Value lists, IP lists, Templates, CORS policies, Issuers, Settings.
- [Release](release.md): Tests and simulate, Publish, Versions.
- [Admin](admin.md): Audit log, Users and tokens, Account.

## Using the admin UI

The admin UI is served by the admin service. Sign in with a username and password.

- Menu items you lack the permission for are hidden, and opening such a page by its address says your role cannot open it.
- On a narrow screen the menu opens from **Menu** at the top, beside **Find**.
- The info mark beside a page or card title explains it; hover over it or click it.

The bar at the top of every screen shows where policy stands, in the order a change travels:

- The shared draft, such as **Unsaved edits**, **Same as live**, or what is **Not published**, such as `1 rule changed`. While a canary runs, the draft is compared with the canary.
- A canary, if one runs.
- The live version.

## Time range

One **Time range** is shared by the dashboard, **Rules**, a rule's **Traffic** card, **Stats**, a client's page, **Routes**, a route's page, the period view of the **War room** and **Audit log**.

- Choices: the last hour, 6 hours, 24 hours (the default), 7 days or 30 days.
- The address keeps it as `?range=1h`, `6h`, `7d` or `30d`, and links carry it to the next screen. A range picked on the dashboard holds on the others and in a bookmarked or shared link.
- On the dashboard, **Rules**, a rule's **Traffic** card, **Stats** and a client's page, **Auto-refresh** beside it means the figures refresh: every 10 seconds up to 24 hours, and every minute for longer ranges.
- **Auto-refresh** reads **Not updating** when the figures can't refresh.

## Find

Find jumps to a page, setting, rule, route, version, user, client or autopilot item by typing part of its name.

- Open it with **Find** (in the sidebar, or in the top bar on a narrow screen) or Cmd+K (Ctrl+K on Windows and Linux) on any screen.
- Arrow keys move through the matches and Enter opens one.
- Every word you type must appear. An exact name comes first, then names that start with the text as a whole word, then names that start with it.

What you can type:

| Type | Opens |
|---|---|
| Part of a page name, such as `audit` | That page |
| A settings section (**Kill switch**, **Trusted client allowlist** or **Rollback guard**) | **Settings** at that card |
| A rule ID | That rule |
| A live autopilot rule ID | The case that made it |
| A route (method, host and path) | That route |
| A version number or message | That version |
| A username | That user |
| An autopilot case (`Case 12`) or note (`Note 3`, or words from its statement) | That case or note |
| A whole IP address or AS number, such as `203.0.113.24` or `AS64500` | That client's page |

??? note "Details"
    - Type an IPv6 client as **Stats** shows it, by its /64, such as `2001:db8:1:2::/64`.
    - Find offers only what your role can open: pages need the right to open them, users need the admin role, and settings sections need the right to read config.
    - Routes and clients need the right to read stats.
    - Autopilot rules, cases and notes need the right to read autopilot.

## Roles

| Role | Can |
|---|---|
| viewer | Read config, stats, the audit log and autopilot (`autopilot.read`) |
| editor | Viewer, plus edit the draft, run tests and acknowledge dashboard items |
| publisher | Editor, plus publish, revert and run canaries, delete or group routes, and investigate, approve and retire autopilot rules (`autopilot.manage`) |
| admin | Publisher, plus manage users, tokens and settings |
