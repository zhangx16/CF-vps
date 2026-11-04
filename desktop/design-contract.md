# NCV Desktop UI contract

Reference: the existing NCV dashboard in `../static/`, inheriting the user's selected neutral shadcn layout: sidebar navigation, white panels, neutral borders, dark primary buttons, restrained status colors. System fonts replace the website's font files so the executable remains self-contained.

Tokens in `ui/style.css`: gap 16px, base font 14px, scale 1.3, measure 1260px, radius 8px, ink #18181b, white surface, line #e4e4e7, edge 28px, room 24px, no shadows, transition 120ms ease. Main text and secondary text use accessible contrast on white. Existing code is the source for layout and components; no new visual template was introduced.

Anchors: sidebar, header, metrics, workspace, website, results. Runtime files: ui/index.html, ui/style.css, ui/app.js. Conditional states: empty table, active task, paused/resumed task, completed task, invalid input, API disconnected, import status, filtered/paginated results. Browser tests cover 1440 and 390px widths, empty state, validation, and horizontal overflow. Native Windows browser integration remains untested. Product runtime contains no review panel.
