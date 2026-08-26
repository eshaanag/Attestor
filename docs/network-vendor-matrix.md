# PS26155 network-vendor evidence matrix

This document records the evidence gate for adding network vendors.
The dashboard must not claim a vendor is implemented until its corpus, source
controls, parser, and pass/fail oracle are all committed and tested.

## Cisco IOS — implemented

- Engine: `engines/network/run_audit.py`
- Corpus: ten source-backed IOS/IOS-XE reference configurations
- Rules: fourteen CIS Cisco IOS controls with defensible NIST SP 800-53 mappings
- Evidence: every included rule has both pass and fail states in the genuine
  corpus; unreadable input fails closed.

## Juniper Junos — implemented scoped subset

Public source material inspected:

- `JNPRAutomate/ansible-junos-evpn-vxlan`, MIT license, commit
  `1d66fc780c568b3499dfaacca34f55bffa693768`. It contains ten Junos `.conf`
  files for fabric, leaf, and spine devices.
- `ckishimo/juniper_display_set`, Apache-2.0 license, commit
  `e466e02bd0c44f763279e2f4e8214126c4b26bbc`. It contains seven Junos example
  `.conf` files, including service, SSH, syslog, and SNMP variants.
- Official Juniper CLI references verified for SSH, syslog, NTP, and SNMP
  syntax. These are the source candidates for implementation rules; no
  unsupported CIS Junos benchmark claim is being made.

Observed coverage:

- Telnet and FTP are enabled in some examples and absent in others.
- SSH is present in multiple service blocks, including variants with
  `root-login allow`.
- Syslog and NTP are present in the ten fabric configs and selected examples,
  absent in other examples.
- SNMP public-community syntax is present in multiple examples.
- Hostname and root-authentication blocks are present in most examples.

Implemented controls:

- Telnet service absent
- FTP service absent
- System syslog block present
- Default SNMP `public` community absent

Each control is a vendor-documentation-backed `junos-baseline` rule, not a
claim of a CIS Junos benchmark. The six retained fixtures have four pass/fail
oracles: Telnet 4/2, FTP 5/1, syslog 4/2, and public SNMP 5/1. The parser is a
small brace-aware subset and rejects unbalanced or unsupported syntax.

Out of scope for this release: SSH root-login, NTP, and broader Junos rules.
Those statements were observed in source material but are excluded because
the retained corpus does not provide the required verified pass/fail evidence.

SSH root-login, NTP, and broader Junos coverage remain unverified and are not
included in the rule pack. Junos is implemented only for the four controls
listed above; it must not be presented as full Junos compliance coverage.

## Other vendors

Arista EOS, Palo Alto, Fortinet, Check Point, Huawei, MikroTik, and other PS
examples remain roadmap candidates. No vendor selector or support claim should
be added for them without the same evidence gate.
