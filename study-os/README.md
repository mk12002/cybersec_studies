# Cybersecurity Study OS

A standalone, portfolio-ready web app that provides:
- 12-week study planner
- Daily tracker with XP scoring
- Adaptive recommendations engine
- Analytics (weekly trend + domain mix)
- Certification Intelligence Pages (dashboard, country deep-dive, compare tool, weekly brief)

## Why this fits your portfolio

This is a productized companion app that aligns with your portfolio identity:
- dark cyber aesthetic with neon green accents
- Inter + JetBrains Mono typography
- scanline/glow motifs consistent with your current site language

## Run locally

Option 1 (Python):

```bash
cd study-os
python -m http.server 8080
```

Open: http://localhost:8080

Certification module entry:
- http://localhost:8080/cert-intel/index.html

Option 2 (VS Code Live Server):
- Open `study-os/index.html`
- Start Live Server

## Deploy on Vercel

1. Push this repository to GitHub.
2. In Vercel, import the repo.
3. Set project root directory to `study-os`.
4. Framework preset: `Other`.
5. Build command: none.
6. Output directory: `.`

This deploys as a static app.

## Integrate into your portfolio

### Option A: Open in new tab (recommended)
Add a CTA button in your portfolio hero/projects section:
- Label: `Launch Cybersecurity Study OS`
- URL: your deployed Study OS URL

### Option B: Embed as a section in your portfolio page
Use an iframe in a dedicated section:

```html
<section id="study-os">
  <h2>Cybersecurity Study OS</h2>
  <iframe
    src="https://your-study-os-domain.vercel.app"
    title="Cybersecurity Study OS"
    style="width: 100%; min-height: 900px; border: 1px solid rgba(255,255,255,0.15); border-radius: 16px;"
    loading="lazy"
  ></iframe>
</section>
```

### Option C: Pull into another repo via git subtree

In your portfolio repository:

```bash
git remote add cybersec-studies https://github.com/<your-user>/cybersec_studies.git
git subtree add --prefix projects/study-os cybersec-studies main --squash
```

For future updates:

```bash
git subtree pull --prefix projects/study-os cybersec-studies main --squash
```

If your portfolio is Next.js, use `public/projects/study-os` as the prefix.

## Data model

All app data is browser-local using `localStorage` key:
- `cyberStudyOS.v1`

Stored objects:
- `profile`
- `plan`
- `sessions`

Includes import/export JSON for backup and migration.

## Future module integration

Planned extension points:
1. `cert-intel/index.html` - Global Certification Intelligence Dashboard
2. `cert-intel/country.html` - Country-specific deep dives
3. `cert-intel/compare.html` - Side-by-side certification comparison
4. `cert-intel/weekly-brief.html` - Weekly execution brief generator

You can expose each module as:
- independent routes in a React shell later
- or separate static pages linked from the same top nav

## Suggested portfolio project writeup structure

Use this app as a case study with:
1. Problem statement: learners struggle with consistency and tactical planning.
2. Product strategy: planner + tracker + adaptive recommendations.
3. Technical design: local-first architecture, analytics, modular expansion.
4. Outcome: measurable progression and reusable study workflow.
