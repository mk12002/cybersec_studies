# Certification Intelligence Pages

This module adds portfolio-ready certification intelligence pages powered by JSON data files.

## Pages

- `index.html`: Global Certification Intelligence Dashboard
- `country.html`: Country deep-dive (India, US/CA, UK, EU, Singapore, UAE/Gulf, Australia/NZ)
- `compare.html`: Compare up to 4 certifications with country + role context
- `weekly-brief.html`: Generate 7-day study brief linked to role and country goals

## Data Layer

All rendering is data-driven from:

- `data/certifications.json`
- `data/countries.json`
- `data/cert_country_scores.json`
- `data/learning_paths.json`

Current coverage in the upgraded dataset:

- 38 certifications across foundational, cloud, governance, privacy, SOC/detection, AppSec, and offensive tracks
- 15 high-opportunity security job markets with country-level context
- Full country score matrix coverage for all certifications across all listed countries
- 7 role profiles and 4 structured learning paths with phase milestones
- 3 weekly planning templates for execution-oriented study flow

Update these JSON files to refresh market snapshots or certification details without changing UI code.

Recommended maintenance workflow:

1. Refresh pricing and renewal details quarterly from official vendor pages.
2. Recalibrate country score matrix based on current job-posting trends and hiring behavior.
3. Update role pathways every 6 months for new tooling and role expectation changes.
4. Record notable market shifts (visa policy, cloud platform demand, compliance changes) in country notes.

## How to Run

From `study-os`:

```bash
python -m http.server 8080
```

Open:

- `http://localhost:8080/cert-intel/index.html`

## Notes

- This is designed as a portable static module so you can copy or subtree it into your main portfolio repo.
- Scores are intentionally relative (1-5) and should be recalibrated quarterly using your updated research.
- Weekly brief output is tactical guidance; use it with your main Study OS tracker for execution evidence.
- Data uses a conservative fallback model in the app for future partial updates so rankings remain stable even if one score row is missing.
