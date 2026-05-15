# Mini-Project Starter Files

This directory contains skeleton files for the Week 10 mini-project. Copy them into your submission directory (`mini-project/submission-<your-handle>/`) and fill in the placeholders marked `TODO`.

## Inventory

| File                              | Purpose                                                   |
|-----------------------------------|-----------------------------------------------------------|
| `topology-template.md`            | ASCII topology diagram + addressing plan + flow matrix    |
| `ruleset-template.nft`            | Skeleton nftables ruleset for the gateway                 |
| `suricata-template.yaml`          | Skeleton `suricata.yaml` with the keys you must edit      |
| `wg0-server-template.conf`        | Skeleton WireGuard server config                          |
| `wg0-client-template.conf`        | Skeleton WireGuard client config                          |
| `allowed-flows-template.md`       | The flow-matrix template                                  |
| `runbook-template.md`             | The three-operation runbook template                      |

## How to use

1. Copy the directory to your submission: `cp -r starter ../submission-<your-handle>`.
2. Rename the templated files (drop the `-template` suffix).
3. Open each in your editor and search for `TODO`. Fill them in.
4. Verify the ruleset applies (`sudo nft -f ruleset.nft` on a VM you can recover).
5. Verify the suricata.yaml parses (`sudo suricata -T -c suricata.yaml`).
6. Verify no private keys are committed (`grep -rE '^[A-Za-z0-9+/]{43}=$' . | grep -v public`).

## Authorised-use reminder

Every artefact in this starter contains a header line declaring authorised use. Do not remove those headers when you adapt the file; replace the placeholder content beneath them but keep the header intact. Re-read the week README banner.
