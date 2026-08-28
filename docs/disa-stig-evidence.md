# Cisco IOS DISA STIG Evidence Gate

## Decision

Attestor does not currently claim native DISA STIG coverage. The official
current Cisco IOS packages were retrieved and inspected, but the genuine Cisco
corpus does not prove both a compliant and noncompliant state for any complete
DISA requirement that overlaps the existing CIS rule pack.

No DISA identifier has therefore been added to a rule. Similar titles are not
treated as equivalent controls.

## Official source evidence

The source catalog is the DISA Cyber Exchange STIG document library:

`https://www.cyber.mil/stigs/downloads/`

The rendered catalog identified these unclassified packages on 2026-08-28:

| Package | Catalog upload | SHA-256 |
|---|---:|---|
| [Cisco IOS Router STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Cisco_IOS_Router_Y26M07_STIG.zip) | 2026-07-10 | `1b5b0b54840abe3f373e9712d7099c60ad3295f01d690b235f66556c75dc131a` |
| [Cisco IOS Switch STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Cisco_IOS_Switch_Y26M07_STIG.zip) | 2026-07-10 | `3a102fbe1eb184500c0a6d8d04352a7fbd0c94d4fa45857e97fe18bfeda1dae3` |

The packages contain these manual XCCDF benchmarks:

| Benchmark | Version/release | Benchmark date |
|---|---|---:|
| Cisco IOS Router NDM STIG | Version 3, Release 8 | 2026-07-01 |
| Cisco IOS Router RTR STIG | Version 3, Release 4 | 2025-10-01 |
| Cisco IOS Switch L2S STIG | Version 3, Release 2 | 2026-07-01 |
| Cisco IOS Switch NDM STIG | Version 3, Release 8 | 2026-07-01 |
| Cisco IOS Switch RTR STIG | Version 3, Release 3 | 2026-04-01 |

The catalog and XCCDF mark the material unclassified. The XCCDF
`terms-of-use` notice is empty and no explicit redistribution license was found.
Attestor therefore records the official URLs and hashes but does not vendor or
redistribute the packages.

## Equivalence review

The following are the closest overlaps with existing Cisco CIS rules. None is
safe to publish as an additive DISA mapping in its current form.

| Existing rule | Closest official DISA requirement | Why a mapping was rejected |
|---|---|---|
| `1.2.1`, `1.3.1`, `1.3.3` | Router `V-215687` / Switch `V-220595`, `CISC-ND-000620` | The router XCCDF checks `service password-encryption`; the switch also requires an enable secret example. Presence of a username or enable secret does not establish the complete requirement or approved algorithm. The existing rules apply to both router and switch inputs. |
| `1.4.1` | Router `V-215669` / Switch `V-220577`, `CISC-ND-000160` | DISA requires the Standard Mandatory DoD Notice and Consent Banner before access. The CIS rule only establishes that a MOTD banner exists. |
| `1.5.9`, `1.5.10` | Router `V-215696`/`V-215697`; Switch `V-220604`/`V-220605`, `CISC-ND-001130`/`001140` | The XCCDF requires group, view, host, user, HMAC, and operational `show snmp user` evidence. Its privacy example uses AES-256. The existing flat checks prove only a subset, and the corpus uses AES-128. |
| `2.3.2` | Router `V-215691` / Switch `V-220599`, `CISC-ND-000980` | DISA requires an explicitly sized logging buffer. The current CIS regex accepts any nonempty `logging buffered` argument and is not equivalent. |
| `2.3.4` | Router `V-220136` / Switch `V-220620`, `CISC-ND-001450` | DISA requires at least two central syslog servers. The current rule requires one; the only corpus pass contains one. |
| `2.3.5` | Router `V-215692` / Switch `V-220600`, `CISC-ND-001000` | The XCCDF treats informational as the default and notes that the command may be absent. The current CIS rule requires an explicit command, so it cannot represent the DISA result. |
| `2.4.1`-`2.4.4` | Router `V-215698` / Switch `V-220606`, `CISC-ND-001150` | The XCCDF requires the complete authenticated NTP configuration and explicitly states that IOS MD5 incurs a permanent finding because it is not FIPS compliant. The CIS rules only prove the documented partial mitigation. |
| `2.6.1` | Router `V-215699`/`V-215700`; Switch `V-220607`/`V-220608`, `CISC-ND-001200`/`001210` | SSHv2 alone is insufficient. DISA also requires approved SHA-2 HMAC and AES-CTR encryption algorithm configuration. Those commands are absent from the corpus. |

## Corpus result

The ten source-tracked IOS/IOSv/IOSvL2 configurations contain both states for
the existing 14 CIS controls. They do not contain a complete DISA-compliant pass
for the requirements above:

- one configuration has one remote logging host, while DISA requires two;
- the SNMP example uses AES-128, while the current XCCDF example requires AES-256
  plus operational evidence;
- no configuration has the required SSH MAC and encryption algorithm commands;
- IOS NTP MD5 is explicitly a permanent DISA finding;
- the existing banners are not the mandatory DoD notice.

Native DISA work remains gated on a source-tracked corpus with both pass and
fail states for each complete automated requirement. Until then, the dashboard
must not expose a native DISA view or describe organization-defined mappings as
Attestor-verified STIG coverage.
