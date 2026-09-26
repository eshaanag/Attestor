# PS26155 Demo Video Script - 2 Minutes

## 0:00-0:12 - Problem

"Modern organizations run devices from many vendors, but their configuration
syntax is incompatible. Manual compliance checks are slow and vendor-locked
tools are difficult to extend. Attestor creates one local source of truth."

Show the landing page and network diagram.

## 0:12-0:38 - Real deterministic audit

Open the audit console. Bulk upload the two genuine Cisco corpus configs.

"Each file is processed independently against source-backed Cisco controls.
Attestor never defaults missing evidence to pass."

Show pass/fail summaries, inventory rows, then open device detail with severity,
evidence, history, and JSON/HTML/PDF links.

## 0:38-1:17 - Training loop

Open Training Studio. Upload the genuine SNMP/syslog Cisco config and
`SOURCES.md`.

"For unfamiliar syntax, raw configuration is discarded after hashing. Attestor
stores redacted patterns, shows the estimated Haiku cost, and requires a hard
call cap. AI suggestions remain unconfirmed until an administrator accepts or
corrects them."

Confirm `service timestamps log datetime msec` as logging. Create a draft
profile, add the source-referenced rule, and publish it.

## 1:17-1:42 - Reuse on another device

Return to the console and select the new organization-defined profile. Upload
both configs.

"The same rule passes where the timestamp command exists and fails where it is
absent. The PDF clearly states that this is an organization-defined profile and
shows operator-authored remediation."

Open the custom PDF notice and failed remediation.

## 1:42-2:00 - Evidence and close

"Attestor currently includes verified Cisco IOS plus scoped Junos and FortiOS
adapters, 122 automated tests, and 221 schema-valid rules across the retained platform. The
same foundation already audits Windows and Ubuntu. As a bonus, report hashes can
be chained and anchored on Ethereum Sepolia; only the hash is public."

End on the architecture slide with: deterministic first, AI-assisted onboarding,
offline evidence.
