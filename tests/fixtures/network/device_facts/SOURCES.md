# Device-facts fixture sources

The five `*_show_version.txt` files are unmodified `show version` fixtures from the public
[`networktocode/ntc-templates`](https://github.com/networktocode/ntc-templates)
repository at immutable commit
`c6dca50ea10fe5a23e750748582fddda263fb053`.

The upstream repository licenses these fixtures under the Apache License 2.0.
The files are retained to verify parser behavior against genuine public command
output rather than hand-written sample data. `manifest.json` records the exact
upstream path, immutable raw URL, retrieval date, platform, and SHA-256 for each
file.

`cisco_router1_running_config_redacted.txt` is retained only to prove a
hostname-matched configuration/facts association through the dashboard. Its
source is the MIT-licensed `GrrrDog/TacoTaco` repository at immutable commit
`e8eb41b1b7aa1b2ce1348ced2f141b094af97785`. The committed derivative replaces
three public lab credential values with the literal `<REDACTED>` and makes no
other semantic change. `manifest.json` records both upstream and fixture hashes.
It is not used to claim new Cisco control verification.

Attestor does not treat the fixture contents as a security baseline. They prove
only that optional device identity fields can be extracted when a separately
supplied command output actually exposes them. Missing fields remain unavailable.
