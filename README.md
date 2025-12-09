# React Command-Center Dashboard

A single-page React dashboard that presents portfolio, liquidity, risk, and reporting actions in one workspace. The layout favors quick scanning with live-style badges, priority alerts, and export/admin controls without page hops.

## Getting started

1. Install dependencies (Node 18+ recommended):
   ```bash
   npm install
   ```
2. Run the dev server:
   ```bash
   npm run dev
   ```
3. Build for production:
   ```bash
   npm run build
   ```
4. Preview the production build locally:
   ```bash
   npm run preview
   ```

## Layout highlights

- **Hero + filters**: top hero banner with quick portfolio/view/priority selectors.
- **Overview**: portfolio health card plus operational stats (cash runway, exceptions, reports ready).
- **Risk & liquidity**: grid of VaR/duration/convexity/liquidity coverage, alongside priority alerts and recent activity timelines.
- **Exports & admin**: shortcuts for report generation, controls, and access reviews.

## Customization

- Update labels, numbers, and alerts directly in `src/App.jsx`.
- Adjust styling via the theme tokens and layouts in `src/index.css`.
- Extend components in `src/components/` to add new cards or tables.
