# FortiOS source corpus

This directory contains eight unmodified public command/configuration captures
used for the scoped Fortinet evidence gate. They are reference and lab outputs,
not Attestor-authored configurations and not claimed to represent production
customer devices.

The files come from four independently licensed repositories. `manifest.json`
records immutable source revisions, URLs, licenses, retrieval date, source
SHA-256 values, and the source repository's description of each artifact.

Only three controls have both pass and fail states in this corpus. The manual
oracle is in `manual_expectations.json`. Missing target blocks are `error`, not
pass. SNMPv3, NTP authentication, central syslog, and timeout controls are
intentionally excluded because both states were not proven.
