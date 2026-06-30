# Module 15 — Excel for Auditors

Excel remains the day-to-day analytical workhorse for most audit/GRC work, especially for processing access reports, log exports, and sampling. This module covers the specific techniques most relevant to audit work, with the underlying *why* for each, not just button-clicking instructions.

## 1. Pivot Tables

The single most useful Excel feature for audit data analysis — summarizing large datasets (e.g., a 10,000-row AD access export) into meaningful aggregated views without writing formulas.

### Audit Use Cases
- **Population analysis:** Pivot a full user access export by Department × Account Status to quickly identify, e.g., how many enabled accounts exist per department, as a starting point for sampling or completeness checks.
- **Exception summarization:** After testing a sample, pivot the results by Exception Type × Severity to summarize findings for the audit report.
- **SoD conflict frequency:** Pivot a list of identified SoD conflicts by Conflict Type × Business Unit to spot whether a particular conflict is concentrated in one area (suggesting a process gap there specifically) versus spread evenly (suggesting a broader systemic issue).

### Practical Tip
Always pivot from a properly structured **flat table** (one row per record, consistent column headers, no merged cells, no blank rows) — messy source data is the most common reason pivot tables produce misleading results in practice.

## 2. VLOOKUP

Looks up a value in the leftmost column of a range and returns a corresponding value from a specified column to the right.

```excel
=VLOOKUP(lookup_value, table_array, col_index_num, [range_lookup])
```

### Classic Audit Use Case
Reconciling two populations — e.g., matching a list of terminated employees from HR against a list of AD account disable events, to identify any terminated employee **without** a matching disable record (a potential Leaver control gap, Module 4).

```excel
=VLOOKUP(A2, 'AD_Disable_Export'!A:C, 3, FALSE)
```
Using `FALSE` for exact match is essentially mandatory in audit work — approximate match (`TRUE` or omitted) can silently return incorrect results when testing for exact identifier matches like employee IDs or usernames, which is a serious risk in audit testing where accuracy is paramount.

### Key Limitation
VLOOKUP only looks **rightward** from the lookup column and only returns the **first** match — both of which are limitations that XLOOKUP (below) resolves.

## 3. XLOOKUP

The modern replacement for VLOOKUP/HLOOKUP/INDEX-MATCH combined, available in current Excel/Microsoft 365.

```excel
=XLOOKUP(lookup_value, lookup_array, return_array, [if_not_found], [match_mode], [search_mode])
```

### Why XLOOKUP Is Preferred for New Audit Work
- Can look up and return values in **any direction** (left or right), unlike VLOOKUP.
- Has a built-in `[if_not_found]` parameter, avoiding the need to wrap in `IFERROR()` separately — directly useful for the exact reconciliation use case above (e.g., return "NOT FOUND - POTENTIAL GAP" directly for any terminated employee with no matching disable record).
- Defaults to exact match (the opposite of VLOOKUP's default), reducing a common source of audit error.

```excel
=XLOOKUP(A2, AD_Disable_List, AD_Disable_Date, "NO MATCH FOUND - REVIEW")
```

## 4. INDEX MATCH

The classic two-function combination that predates XLOOKUP but remains extremely common (especially in organizations not yet on the Microsoft 365 subscription version of Excel, where XLOOKUP isn't available).

```excel
=INDEX(return_range, MATCH(lookup_value, lookup_range, 0))
```

`MATCH(..., 0)` specifies exact match (the `0` is critical — same exact-match principle as VLOOKUP's `FALSE`). INDEX/MATCH's key historical advantage over VLOOKUP was direction-flexibility (the same advantage XLOOKUP now provides more simply) — worth knowing both since you'll encounter INDEX/MATCH in older workpapers and templates even as XLOOKUP becomes the default for new work.

## 5. Conditional Formatting

Visually highlighting cells that meet specific criteria — extremely useful for **rapid visual exception identification** across large datasets.

### Audit Use Cases
- Highlight any row where a calculated "days between termination date and disable date" exceeds the policy SLA (e.g., `=B2>1` for a 24-hour/1-day SLA, formatted red).
- Highlight duplicate values (built-in "Highlight Cell Rules → Duplicate Values") — directly useful for finding duplicate user accounts or duplicate vendor records (a classic fraud-detection technique, since duplicate vendor records with slightly different names/addresses are a known fraud pattern).
- Color-scale formatting on a risk score column to visually triage a large population before deciding where to focus sampling.

## 6. Duplicates

Identifying and handling duplicate records is a recurring audit data-quality task.

### Techniques
- **Conditional Formatting → Duplicate Values** (visual identification, covered above).
- **Remove Duplicates** (Data ribbon) — use cautiously; this permanently removes rows, so always work on a **copy** of the original evidence file, never the original export received from the client (preserving the original, unaltered evidence is itself an evidence-integrity best practice — Module 8).
- **COUNTIF for duplicate flagging without deletion** (preferred for audit work, since it preserves all original data while flagging duplicates for review):
```excel
=COUNTIF(A:A, A2)>1
```

### Why Duplicates Matter for Specific Audit Tests
- Duplicate vendor master records (potential fraud vector, Module 4's classic SoD example).
- Duplicate employee/user accounts (could indicate an orphan account scenario, Module 5, or a control gap where re-provisioning created a second account instead of reactivating the original).
- Duplicate transaction records (potential duplicate payment risk).

## 7. Sampling (Excel-Based Techniques)

Building on Module 9's sampling concepts, here's how it's actually executed in Excel for a population without a dedicated audit sampling tool.

### Random Sampling
```excel
=RAND()
```
Add a random number column to the full population, then sort by that column and take the top N rows as your sample — this ensures every record has an equal, unbiased chance of selection (a core sampling integrity requirement from Module 9).

### Systematic Sampling
Selecting every *n*th record after a random start point (e.g., population of 500, desired sample of 25 → sampling interval of 20; randomly pick a starting point between 1-20, then select every 20th record thereafter). Useful when a true random number generator isn't available/permitted by methodology, though true random sampling is generally preferred where feasible.

### Stratified Sampling
Dividing the population into meaningful subgroups (strata) — e.g., by risk tier, business unit, or transaction size — and sampling proportionally or specifically from each stratum, rather than treating the whole population as homogeneous. This matters when risk isn't evenly distributed (e.g., you might deliberately over-sample High-risk transactions relative to their proportion of the total population, since they carry more audit risk per instance).

## 8. Filters

Basic but essential — AutoFilter and Advanced Filter for narrowing a dataset to relevant records before analysis (e.g., filtering an access export to only enabled accounts in financially-relevant systems before beginning population analysis).

### Advanced Filter vs. AutoFilter
Advanced Filter supports more complex multi-criteria logic and can extract results to a separate range (useful for preserving the original full dataset untouched while working with a filtered subset) — generally preferred over AutoFilter for any analysis that will become part of a formal workpaper, since the filtered criteria can be documented and reproduced.

## 9. Power Query

Excel's data transformation and ETL (Extract, Transform, Load) tool — increasingly essential for audit work involving large, messy, or recurring data extracts.

### Why Power Query Matters for Auditors Specifically
- **Repeatable transformations:** Build a query once (e.g., "import this AD export, filter to enabled accounts, remove duplicate UPNs, merge with the HR termination list") and re-run it on next quarter's data with one click — critical for recurring quarterly/annual testing where the same transformation logic needs to be applied consistently.
- **Merge/Join operations** (similar to SQL joins) — directly useful for the HR-to-IT reconciliation use case (Module 4/8), often more robust and transparent than nested VLOOKUP/XLOOKUP formulas for complex multi-column matching.
- **Auditability of the transformation itself:** Power Query's step-by-step applied transformation log is itself a form of documentation — a reviewer can see exactly what transformations were applied to get from raw export to final analysis, which strengthens the defensibility of the resulting conclusion (tying back to Module 8's evidence-quality principles).

## 10. Large Access Reports — Practical Workflow

Putting it together, a typical workflow for processing a large (e.g., 50,000+ row) access export for a quarterly access review test:

1. **Import via Power Query** (handles large files more gracefully than direct paste, and creates a reproducible transformation log).
2. **Clean and standardize** — remove duplicates (COUNTIF flag, then manual review — never blind auto-delete), standardize date formats, trim whitespace from text fields (a very common source of failed lookups — `=TRIM()`).
3. **Reconcile against the independent source population** (e.g., HR active employee list) using XLOOKUP/INDEX-MATCH or a Power Query merge, flagging mismatches.
4. **Pivot for population analysis** — understand the shape of the data (how many records, by department/system/status) before sampling.
5. **Apply sampling methodology** (random/systematic/stratified per Module 9's risk-based approach) to select the test sample.
6. **Conditional formatting** to visually flag exceptions as testing results come in.
7. **Summarize via pivot table** for the final findings write-up (Module 10).

---
**Quick Self-Check Questions**
1. Why is `FALSE` (exact match) essentially mandatory when using VLOOKUP in audit reconciliation work?
2. What two specific limitations of VLOOKUP does XLOOKUP resolve?
3. Why should an auditor never use "Remove Duplicates" directly on an original evidence file received from a client?
4. Explain stratified sampling with an original example relevant to IT access testing.
5. Why is Power Query's applied-steps log itself a form of audit evidence/documentation, not just a convenience feature?
6. Walk through, in order, a practical workflow for processing a large access export from import to final findings summary.
