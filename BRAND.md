# Brand: Mono

The admin UI (`web/admin`) is achromatic and precise: near-white or pure black canvases, `#171717` and `#EDEDED` ink, edges drawn as 1px shadows instead of borders, and Geist Sans and Geist Mono throughout. Colour appears only where it means something: red, amber and green for status, and blue for focus.

The UI follows the system setting (`prefers-color-scheme`). There is no theme switch.

Every value below is a token in `web/admin/src/index.css`: the light values in `@theme`, the dark values in the `prefers-color-scheme: dark` block, which redefines the same variables so every utility flips without a `dark:` variant. Use the token's Tailwind class, never a raw hex or a stock palette class such as `slate-*`, `red-*` or `zinc-*`.

## Colour

### Neutrals

| Token | Light | Dark | Tailwind | Use |
|---|---|---|---|---|
| Page | `#FAFAFA` | `#000000` | `bg-page` | The canvas behind everything |
| Panel | `#FFFFFF` | `#0A0A0A` | `bg-panel` | The sidebar, cards, tables, inputs, dialogs, the release strip |
| Soft | `#F5F5F5` | `#1A1A1A` | `bg-soft` | Hover on rows, links and default buttons; the current nav link; `pre` blocks |
| Heading | `#171717` | `#EDEDED` | `text-heading` | Headings, labels, values, primary text |
| Body | `#4D4D4D` | `#A1A1A1` | `text-body` | Paragraphs, hints, nav links at rest (the `body` default) |
| Muted | `#666666` | `#8F8F8F` | `text-muted` | Captions, table heads, placeholders, the release strip's labels |
| Line | `#EBEBEB` | `#2E2E2E` | `border-line`, `divide-line` | Separators inside a panel: table rows, rule lists, the sidebar edge |
| Ring | black at 8% | white at 14% | `shadow-ring`, `shadow-card` | The 1px edge of cards and tables |
| Field | black at 14% | white at 20% | `shadow-field` | The 1px edge of inputs, default buttons and the info icon, stronger so controls read as controls |

### Ink and interaction

| Token | Light | Dark | Tailwind | Use |
|---|---|---|---|---|
| Brand | `#171717` | `#EDEDED` | `bg-brand` | Primary buttons, the `Draft` pill, the open info icon, checkboxes |
| Brand hover | `#383838` | `#CCCCCC` | `hover:bg-brand-hover` | Primary button hover |
| On brand | `#FFFFFF` | `#0A0A0A` | `text-on-brand` | Text on brand |
| Tip | `#171717` | `#1F1F1F` | `bg-tip` | Tooltips |
| On tip | `#FAFAFA` | `#EDEDED` | `text-on-tip` | Tooltip text |
| Focus | `#006FF5` | `#006FF5` | `outline-focus` | Every focus outline, drop indicators in the rule builder |

### Status

Status is a tinted wash with the tone's text, never colour alone: every status also has a word (`active`, `live`, the error message), and errors use `role="alert"`.

| Tone | Text | Wash | Light text / wash | Dark text / wash | Used by |
|---|---|---|---|---|---|
| Danger | `text-danger` | `bg-danger-wash` | `#C4141C` / `#FFEBEB` | `#FF6166` / `#2A0E0F` | `ErrorBox`, `Issues`, `Badge tone="red"`, field errors, danger buttons |
| Warning | `text-warning` | `bg-warning-wash` | `#9A5B00` / `#FFF5E0` | `#F5B544` / `#2A1E05` | `Issues tone="amber"`, the one-time token notice |
| Success | `text-success` | `bg-success-wash` | `#107D32` / `#E8F7EC` | `#4FD97A` / `#0B2A16` | `Notice`, `Badge tone="green"`, the active-version banner, the live dot |

`bg-danger-solid` (`#C4141C`, hover `#A51017`, white text) is only the final button of a `Confirm`.

### Contrast

WCAG 2, normal text, minimum 4.5:1. The lowest pairing of each colour across page, panel and soft:

| Colour | Light | Dark |
|---|---|---|
| Heading | 16.4:1 | 14.9:1 |
| Body | 7.8:1 | 6.7:1 |
| Muted | 5.3:1 | 5.4:1 |
| Danger, warning, success on page, panel and soft | 4.8:1 to 6.1:1 | 5.9:1 to 11.6:1 |
| Danger, warning, success on their wash | 4.7:1 to 5.3:1 | 6.1:1 to 9.0:1 |
| On brand | 17.9:1 | 16.9:1 |
| On tip | 17.2:1 | 14.1:1 |
| White on danger solid | 6.1:1 | 6.1:1 |

The focus colour is 4.6:1 against both white and black, above the 3:1 non-text minimum.

## Typography

| Role | Font | Size / weight / line height | Tracking |
|---|---|---|---|
| Page title (`h1`) | Geist | 32px / 600 / 1.25 | -0.04em |
| Section title (`h2`, card and dialog titles) | Geist | 20px / 600 / 1.4 | -0.02em |
| Body (the `body` default) | Geist | 16px / 400 / 1.5 | normal |
| Controls, tables, nav links, hints | Geist | 14px (`text-sm`), 500 for buttons and links | normal |
| Badges, the `Draft` pill | Geist | 12px (`text-xs`) / 500 | normal |
| Technical labels (`eyebrow` utility) | Geist Mono | 12px / 500, uppercase | normal |
| Code | Geist Mono | 13px in `pre`, 14px in editors | normal |

Three weights with fixed roles: 400 for reading, 500 for anything you can act on, 600 for headings. Tracking is negative on headings and never positive. Headings use `text-wrap: balance`. `h3` is Geist `text-sm` at 500 or 600, for subsections inside a card.

`eyebrow` labels table heads, nav groups, the release strip's parts and chart captions: the console voice, kept for labels, never sentences.

Fonts are bundled from `@fontsource-variable/geist` and `@fontsource-variable/geist-mono` (OFL-1.1) because the admin CSP is `default-src 'self'` and blocks font CDNs.

## Shape and depth

| Token | Value | Tailwind | Use |
|---|---|---|---|
| Control radius | 6px | `rounded-control` | Buttons, inputs, selects, editors, nav links, alerts, `pre` |
| Card radius | 8px | `rounded-card` | Cards, tables, the release strip, the save bar, tooltips, rule builder groups |
| Dialog radius | 12px | `rounded-dialog` | Dialogs, the sign-in panel |
| Pill | full | `rounded-full` | Badges, the `Draft` pill, the info icon. Never a button |

| Shadow | Value | Use |
|---|---|---|
| `shadow-ring` | 1px ring | A plain edge |
| `shadow-field` | 1px field ring | Inputs, default buttons, `Sign out`, the info icon |
| `shadow-card` | ring + `0 2px 2px` black at 4% | Cards, tables, the release strip, the sign-in panel |
| `shadow-float` | ring + `0 8px 30px` black at 12% | Things above the page: the save bar, dialogs, tooltips |

- **Edges are shadows, not borders.** A 1px shadow sits outside the box, so a button and a field in a row are exactly the same size. `border-line` is kept for dividers inside a panel and the sidebar's edge.
- **Spacing:** a 4px base. Cards `p-6`, page sections `gap-6`, main content `p-4` (mobile) and `p-8` (desktop).
- **Width:** a page is at most `max-w-6xl`; card intros and help paragraphs are at most `max-w-prose`.
- **Motion:** links and buttons change colour and shadow over 150ms, only when the system allows motion. Nothing moves, scales or fades in.

## Layout

- **Sidebar:** a panel with a `line` edge. From `lg` up it is 240px (`w-60`) and stays in view while the page scrolls: the `EDGE PROXY` label and `Policy Admin` wordmark at the top, links grouped under `eyebrow` labels (Policy, Release, Operate, Access), and the account link with `Sign out` at the bottom. Below `lg` it folds into a bar: wordmark and account on one row, links wrapping below. A link at rest is body text; hover and the current section are soft with heading text, including on nested screens (a rule editor is under Rules).
- **Release strip:** the first thing in the main area on every screen. A card reading DRAFT → CANARY (only while one runs) → LIVE, each part linking to where you act on it. The live version has a green dot.
- **Save bar:** sticky 8px from the top while there are unsaved edits, floating (`shadow-float`), with a brand `Draft` pill.
- **Page:** the `h1` with its info icon and the actions right-aligned on the same row. No rule under it.
- **Login:** the sign-in panel centred on the page.
- **Skip link:** the first focusable element, visible only on focus, jumps to the main content.

## Components

All live in `web/admin/src/ui.tsx`; pages compose them instead of restyling.

| Component | Rule |
|---|---|
| `Button` | `rounded-control`, `px-3.5 py-1.5`, `text-sm font-medium`. `primary` is brand with on-brand text. `default` is a panel with `shadow-field` that goes soft on hover. `danger` is quiet: danger text and a faint danger ring, the danger wash on hover, so a table of destructive actions stays calm. `danger-solid` is only the final button of a `Confirm`. One primary action per view |
| `Input`, `select`, `textarea` | One shell from the base layer: panel fill, `shadow-field`, `rounded-control`, 14px text, 34px tall like `Button`. Focus draws the focus outline. Pages add no input classes. Labels are short nouns; anything that explains the field goes in `hint`, a line under it that is read out with the field |
| `Check` | Native 16px checkbox with `accent-color` brand and a 14px heading label |
| `Card` | Panel, `rounded-card`, `shadow-card`, `p-6`, a `Title`, an optional `intro` and an optional `info`. Static: no hover effects |
| `Title` | An `h2` with its `Info` beside it, outside the heading so the heading's name stays its text |
| `Info` | A 16px pill with a drawn "i" (a glyph reads as "1" at this size), muted with `shadow-field` at rest and brand while open. Opens a tip-coloured tooltip on hover or focus, stays open on click for touch, closes on Escape or a click elsewhere, and shifts left to stay on screen. Its text is the button's description, so screen readers read it on focus. `LabelInfo` places one after a field label without entering the `<label>` |
| `Table` | Panel, `rounded-card`, `shadow-card`, sideways scroll. The head is `eyebrow` in muted text over a `line`; rows divide on `line`. Number columns are listed in `num`: right-aligned and `tabular-nums`. `empty` says what an empty table means and what to do. Below `sm` each row becomes a card, every cell under its column name |
| `Badge` | 12px at 500 in a pill: the tone's wash and text, or soft and heading for neutral |
| `Notice`, `ErrorBox`, `Issues` | The tone's wash, `rounded-control`, `p-3`, `text-sm` |
| `Modal`, `Confirm`, `ConfirmButton` | Native `<dialog>`: panel, `rounded-dialog`, `shadow-float`, `p-6`, the page colour at 80% behind it. Focus starts on Cancel and returns to the opener |
| `pre` | Soft fill, `rounded-control`, 13px mono |
| `CodeEditor` | CodeMirror on the panel with `shadow-field` and the focus outline while focused, at most 32rem tall. Its theme reads the tokens, so it flips with the mode. Syntax is monochrome: keys heading at weight 500, strings and punctuation body, numbers and literals heading italic. Never the default palette, whose red strings read as errors |
| `Reference` | A `line`-bordered disclosure, **Fields and an example**, under every JSON editor |
| Charts | Inline SVG bars in heading ink on a time axis covering the whole range, with `eyebrow` captions for the peak and the start and end times. A chart always has a scale |
| Rule builder | react-querybuilder reads the brand, soft, line and focus tokens and the card radius through its `--rqb-*` variables; its buttons match the default `Button` |

Focus is always visible: `:focus-visible` draws a 2px focus outline with a 2px offset (0 on fields, where the edge is the field).

## Behaviour

- **Every screen names itself.** `Page` sets the tab title and moves focus to its `h1`.
- **Ask before production changes.** Publish, canary step, promote and abort, revert, guard settings, disabling a user and revoking a token open `Confirm`. Edits that only touch the draft do not ask.
- **Never lose edits silently.** Leaving a rule with unapplied changes, an editor holding text that is not JSON, or the tab with an unsaved draft asks first. Discard asks before throwing the draft away.
- **A session that ends mid-edit signs in over the screen**, keeping the draft and the screen's state.
- **Cmd or Ctrl+S** saves the draft from any screen.
- **Pending actions say so:** buttons read Saving…, Publishing…, Running… while their request runs.
- **Explain the concepts that change production** with `Info`, in one to three plain sentences that say what happens, not what the field is called.

## Do not

- Use stock palette classes (`slate-*`, `red-*`, `gray-*`) or raw hex in components, or `dark:` variants: the tokens already flip.
- Add colour to the chrome. Red, amber and green are for status, and blue is for focus.
- Use `border` for a card, button or field edge; use the shadow tokens.
- Use weight 700, positive letter-spacing, or a pill-shaped button.
- Add a new radius, a heavier shadow, a gradient or a second typeface.
- Load fonts, icons or images from another origin. The CSP blocks them.
- Show status by colour alone.
- Leave a primary action disabled without a `Hint` saying why.
- Use the browser's `confirm()` for production changes; use `Confirm`. It is kept only for leave guards, which must run synchronously.
