# Package Assessment: {PKGNAME} {VERSION_DISPLAY}

**Mode:** {MODE}  |  **Ecosystem:** {ECOSYSTEM}
**Work dir:** `{WORK_DIR}`
**SHA256:** `{SHA256}`

---

## License

| Field | Value |
|---|---|
| SPDX | {SPDX} |
| OSI Approved | {OSI_APPROVED} |
| Status | {LICENSE_STATUS} |

**Note:** {LICENSE_NOTE}

---

## Project Health

| Field | Value |
|---|---|
| Age | {HEALTH_AGE} |
| Last release | {HEALTH_LAST_RELEASE} |
| Version stability | {HEALTH_VERSION_STABILITY} |
| Owners | {HEALTH_OWNERS} |
| Scorecard | {HEALTH_SCORECARD} |
| Known vulnerabilities | {HEALTH_KNOWN_VULNS} |

**Concerns:** {HEALTH_CONCERNS}

---

## Scan Results

**Concern level:** {CONCERN_LEVEL}  |  **Risk flags:** {RISK_FLAGS}

[TODO: interpret scan matches; call out bidi/zero-width/prompt
scan hits specifically]

---

## Source Comparison

**Repository:** {CLONE_URL}
**Clone status:** {CLONE_STATUS}
**Extra files in package:** [TODO: count; list non-metadata extras]
**Binary files:** [TODO: count and types, or "none"]
**Source match:** [TODO: EXACT | CLOSE | DIVERGENT | UNKNOWN]

---

## Manifest Findings

**Native extensions:** {EXTENSIONS}
**Executables added to PATH:** {EXECUTABLES}
**Post-install message:** {INSTALL_TIME_HOOKS}
**New runtime deps:** [TODO: list or "none"]

---

## Transitive Dependencies

**Total new packages:** {TRANSITIVE_TOTAL}
**Not in lockfile:** [TODO: list, or "none"]
**Concerns:** [TODO: very new, low downloads, unusual names, or "none"]

---

## Diff Summary (UPDATE mode only)

[TODO: list changed/added/removed filenames; omit for NEW/CURRENT]

---

## Provenance

**MFA status:** {MFA_STATUS}
[TODO: maintainer info, ownership changes]

---

## Risk Factors

**Increasing:** [TODO: list or "none"]
**Decreasing:** [TODO: list or "none"]

---

## Deeper Analysis

**Performed:** [TODO: YES | NO]
**Reason:** [TODO: trigger if YES; why skipped if NO]

---

## Reproducible Build

**Result:** [TODO: EXACTLY REPRODUCIBLE | FUNCTIONALLY EQUIVALENT
  | UNEXPECTED DIFFERENCES | INCONCLUSIVE | SKIPPED]
**Sandbox:** [TODO: tool or "none"]
**Code diffs:** [TODO: count or "n/a"]

---

## Verdict

**RISK_ASSESSMENT:** [TODO: LOW | MEDIUM | HIGH | CRITICAL]
**SUMMARY_RECOMMENDATION:** [TODO: APPROVE | APPROVE_WITH_CAUTION
  | REVIEW_MANUALLY | DO_NOT_INSTALL]

---

## Summary

[TODO: 2-6 sentences on findings and reason for recommendation.
Use risk-based language; never claim safety or give guarantees.
Good: "Update assessed as low risk."
Bad: "Safe to update." "This package is safe."]

---

Write `verdict.json` alongside this file when done:

```json
{
  "summary": "PASTE_SUMMARY_HERE",
  "risk_increasing": "PASTE_RISK_INCREASING_HERE",
  "risk_decreasing": "PASTE_RISK_DECREASING_HERE"
}
```
