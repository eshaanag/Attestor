# Cisco IOS reference corpus

This corpus contains eight unmodified, source-backed Cisco IOS lab/reference
configurations from the MIT-licensed `c4geeks/ccna-labs` repository at commit
[`9cadb5c`](https://github.com/c4geeks/ccna-labs/commit/9cadb5c162a2bf231493a51b5337ab385c5a5962).
The upstream README states that the configurations were built and tested on
real Cisco IOSv, IOSvL2, and c7200 images in GNS3 and links each lab to its
article. The upstream repository and license are retained under `reference/`
for inspection; the copied files here are byte-for-byte unchanged.

These are **reference configuration scripts**, not claims of production
backups or live DevNet Sandbox captures. Several files are paste-ready lab
inputs (including `enable`, `configure terminal`, and `write memory`) rather
than literal `show running-config` output. Live sandbox capture remains a
separate presentation-day step.

Retrieval date: 2026-08-24
Redistribution: permitted by the upstream MIT license; source URL, commit,
article URL, platform, and SHA-256 are recorded in `manifest.json`.

The base-device source documents its passwords as throwaway lab values. They
are retained only because the fixture bytes are preserved for parser testing;
they are not device credentials and must not be used outside a lab.
