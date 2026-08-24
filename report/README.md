# Report

Jinja2-based HTML report generator. Produces standalone, offline-viewable
compliance reports from engine JSON output, showing pass/fail/error/manual per
control with remediation text. Network reports additionally show audited device
identity/config provenance and optional secondary framework mappings (for
example NIST SP 800-53) without requiring network access.

## PDF reports (G')

The additive ReportLab generator produces an offline PDF without replacing the
HTML report:

```bash
python3 report/generate_pdf.py results.json -o report.pdf --state-dir ai/state
```

Failed controls receive a clearly labelled AI-remediation field. Dry-run is the
default and does not write fake responses to the remediation cache. Real
remediation generation requires `--real-api`, `ANTHROPIC_API_KEY`, and a hard
`--max-calls` cap. Cached remediation is keyed by `vendor|platform|rule_id`, so
the same fix is not regenerated per device. The provider receives rule metadata
only; raw config evidence is not sent.

For the Phase E Cisco reference report, 9 controls fail and therefore represent
9 unique remediation keys. A first real remediation run is estimated at about
2,250 input + 1,440 output tokens, approximately `$0.00945` at the published
Haiku 4.5 `$1/$5` per-million-token rates. No real remediation calls have been
approved or made in G'.
