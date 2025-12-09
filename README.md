# React FIM Command Center

A single-page React dashboard for a real-time File Integrity Monitoring (FIM) system. It surfaces create/modify/delete events, baseline health, MITRE-aligned alerts, and governance controls in one view so responders can pivot quickly without navigating between pages.

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

- **Hero + filters**: top banner with directory/time/severity filters and badges for create/modify/delete coverage.
- **Integrity overview**: baseline coverage, chain status, last scan, and change counts for the watched directory.
- **Detection & integrity**: metrics for hash coverage, alert volume, response times, and MITRE-mapped detections alongside alert and action timelines.
- **Governance & export**: controls to download hash-chained audit logs, adjust exclusion policies (to avoid personal data), and verify log-chain integrity.

## Customization

- Update labels, paths, and MITRE mappings directly in `src/App.jsx`.
- Adjust styling via the theme tokens and layouts in `src/index.css`.
- Extend components in `src/components/` to add new cards, tabs, or tables specific to your FIM agent.
