# AI-Assisted Discovery (F')

This package is additive to the deterministic Cisco IOS engine. It measures
active configuration lines that no production `config_grep` rule matched and
classifies only the remaining syntax as discovery metadata. It never changes a
compliance result.

The provider is disabled by default. Before any real call:

```bash
python3 -m ai.network_discovery inventory \
  --json-out tests/fixtures/network/cisco_ios/unmatched_patterns.json
python3 -m ai.network_discovery classify \
  --inventory tests/fixtures/network/cisco_ios/unmatched_patterns.json
```

The second command is explicitly `dry-run` and makes no API request. It returns
clearly labelled placeholders. Credentials and secret values are redacted before
inventory persistence or any future provider request.

A real run requires both `--real-api` and `ANTHROPIC_API_KEY`, plus a positive
`--max-calls` cap. It refuses to start if the number of uncached candidates would
exceed that cap. Provider responses are cached by a versioned normalized-pattern
hash. Human corrections persist separately:

```bash
python3 -m ai.network_discovery confirm \
  --pattern 'service timestamps log datetime msec' \
  --category logging \
  --note 'Confirmed by operator from Cisco IOS syntax'
```

The cache and confirmed mappings are local state and are ignored by git. A
confirmed mapping is training-loop state, not a compliance pass/fail claim.
