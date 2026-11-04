# CF VPS UI design contract

## Source and scope

Main reference: [shadcn/ui dashboard-01, new-york-v4](https://ui.shadcn.com/view/new-york-v4/dashboard-01), selected by the user on 2026-11-02. Implemented using the requested [ui-design-iteration skill](https://git.nite07.com/nite/skills).

The published registry component source and rendered page were saved in `/root/CF-vps-design/reference`. Desktop and mobile reference screenshots, computed styles, and source components are retained there. The source components `page.tsx`, `app-sidebar.tsx`, `section-cards.tsx`, and `data-table.tsx` provide the shell, inset content, card anatomy and table treatment. Their layout, component anatomy, icon treatment and measured values are translated into the existing buildless HTML/CSS application; no React runtime or build dependency is introduced. Geist Latin font is embedded locally; Chinese uses PingFang SC / Microsoft YaHei / platform sans-serif fallback.

## Page and content

A server scanning console whose main task is inspecting progress and filtering/retesting observations.

1. Sidebar and header: navigation and new scan entry point, from reference app sidebar / site header.
2. Four status cards: actual progress, hit count, run speed and estimated time, from section-cards. Reference revenue/customer/trend numbers are never copied into the product.
3. Current task: actual job selector, progress and lifecycle controls. The reference's chart area is replaced with the available real progress data; no synthetic traffic chart is shown.
4. Results: evidence, region, colo, request-time sort and search toolbar; selectable table and cursor pagination, from reference data-table treatment.
5. Comparison: two real job selectors, change category and endpoint lists.
6. Evidence explanation: details disclosure, not an extra card grid.
7. New scan: native accessible modal dialog, with target file import and rate controls.

## Design language and standing decisions

- Light neutral grayscale theme; black primary actions; white inset main surface; near-white sidebar.
- Sidebar width 288px and main inset 8px, measured from reference. Header is 56px.
- Source's Geist font, compact 14px controls/table and 12px secondary notes; section titles 16px, page title 24px and metric numerals 30px. Phone numerals use 24px.
- Source component radii: 8px controls, 14px cards, 16px inset main, pills/circular status indicators. These reference devices override the skill's default two-radius limit.
- Source's subtle gray-to-white metric card gradients and 1px/2px at-rest shadow are deliberate reference devices, overriding the default no-gradient limit. No decorative gradients elsewhere.
- Only two shadow recipes: at-rest component shadow and floating modal/sidebar shadow.
- Muted text darkened from measured #737373 to #666 for readable text on muted surfaces; required accessibility correction.
- 768px navigation breakpoint, with keyboard-accessible drawer; 1200px content breakpoint for compact card/filters. Both sides are checked.
- Dense results intentionally scroll horizontally inside the table container; the page never scrolls horizontally.
- Native controls/dialogs remain native. Confirmation for deletion uses the browser confirmation dialog.

## Bound levers

`:root` is the single design token block in `static/style.css`.

| Lever | Value/source | Mapping |
| --- | --- | --- |
| gap | 16px, source | padding/gaps derive from multiples; fixed reference control/layout dimensions remain explicit |
| fs | 14px, source | five reference type steps mapped as multiples |
| measure | 68ch, adapted to explanation copy | paragraph max width |
| radius | 14px, source cards | control radius derived as 4/7; main as +2px; pills remain pills |
| ink | 0%, measured | foreground/primary lab lightness |
| surface | 100%, measured | background, sidebar -1.74%, muted -3.5% |
| line | 91%, measured | borders in lab lightness |
| edge | 1px, source | component borders |
| shadow | 1, source | at-rest shadow multiplier |
| room | 1.5, source | primary panel separation |
| dur | 160ms, source-aligned | hover transitions; reduced motion sets 0 |
| ease | cubic-bezier(.2,0,0,1) | declared common easing |

`ratio` is intentionally unbound: reference's five steps are not a geometric scale. `hue` is intentionally unbound: the source is neutral grayscale. The review kit exposes only functional levers.

## Anchors

`shell/sidebar`, `shell/main`, `shell/header`, `overview`, `overview/metrics`, `overview/task`, `results`, `results/filters`, `results/table`, `history`, `evidence`, `scan/dialog`.

## Review artifacts and handoff

- Editable offline draft: `/root/CF-vps-design/draft`; its sample data is clearly marked and is not a claim about discovered servers.
- Review runtime and kit: draft-runtime.js, review-config.js, draft-kit.js. These are local review tools only, absent from production.
- Product: static/index.html, static/style.css, static/fonts.css, static/app.js.
- User approved reference; functional integration and deployment are authorized in the same task. This is an agent-reviewed implementation, not a claim of user approval of the finished screen.
- Draft approximations: offline mock API simulates completion; it does not connect to targets or persist real data. Production uses the real backend.
- Screenshot and audit widths: 375, 767, 768, 1200, 1201, 1440px. No page overflow. Normal state has no reported contrast failures at any reviewed width. Table is separately horizontally scrollable.
- Keyboard: native form/dialog focus and Escape; mobile drawer Escape and focus loop; visible focus styles. Native clipboard is used on HTTPS; fallback for non-secure contexts.
- Reference photos, revenue figures, customers, testimonials, graphs and avatars are intentionally absent. No external resource fetch is needed to render the UI.

## Resource and provider additions

The user subsequently requested adaptive concurrency and selectable provider prefix inventories. Runtime resource information is a secondary line in the existing task card, using the established text scale. Provider inventory is a disclosure/table module, reached from the existing sidebar, with no additional card grid. Its selectors, row checkboxes, pagination and custom ASN form reuse the same controls and tables. The scan dialog adds adaptive mode and normal minimum concurrency; the configured concurrency field is explicitly the ceiling. Anchors added: `providers`.

## Result center

The user requested a dedicated left-side results module. A reference-style navigation group exposes all observations, strict confirmations, provider categories and exit-region categories. The main result table is reused in a separate view with provider/task context selectors and source columns; no duplicate card grid is added. Cross-task rows retain their task provenance. Bulk retest requires a single task. Existing filters, sorting, clipboard and CSV continue to work in this view.

## Regional profiles and resume affordance

Provider presets are reduced to DMIT, BWH, GoMami Hong Kong, VMISS United States and ISIF Cloud Hong Kong, as requested. Regional provenance is stated in the existing notes area. Pausing retains the existing checkpoint mechanism; the stop label becomes pause, and a reference-style notice in the overview exposes the last unfinished task with continue/view controls. No automatic resume is performed on page load.

Local desktop integration: existing sidebar link and task-targets accordion styles reused for results/local-validation. Local validation badge and result-type filter retain the original evidence semantics; no region logic changed.
