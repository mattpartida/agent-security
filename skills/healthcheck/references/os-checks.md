# OS Checks Reference

## How to use this file

Read this only when you need concrete host-level checks. Keep the main skill focused on workflow, not long command catalogs.

## Minimal read-only discovery

### macOS
- OS/version: `sw_vers`
- Kernel/arch: `uname -a`
- Listening TCP ports: `lsof -nP -iTCP -sTCP:LISTEN`
- Application Firewall: `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`
- PF status: `pfctl -s info`
- Time Machine: `tmutil status`
- FileVault: `fdesetup status`
- Software update status: `softwareupdate --schedule`

### Linux
- OS/version: `cat /etc/os-release`
- Kernel/arch: `uname -a`
- Listening ports: `ss -ltnup` or `ss -ltnp`
- Firewall: `ufw status`, `firewall-cmd --state`, or `nft list ruleset` depending on what is installed
- Disk encryption: check environment-specific tooling (LUKS layout is not always trivial to infer safely)
- Automatic updates: distro-specific, verify before assuming

### Windows
Use native tooling only when available and appropriate. Prefer recommendations if the environment is not directly inspectable.

## Safety notes

- Do not change firewall or remote-access settings during read-only discovery.
- On remote hosts, do not propose firewall/SSH changes without an access-preservation plan.
- If backups or encryption cannot be verified automatically, ask plainly instead of guessing.
