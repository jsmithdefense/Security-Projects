# Homelab

Security lab work performed on my personal infrastructure — from hypervisor and network design to SIEM/EDR deployment and detection tuning.

- [**ConDef Homelab**](ConDef-Homelab.md) — Purple-team practice lab on Proxmox VE covering Windows Active Directory, ADCS, and detection engineering. Promoted a Windows Server domain controller, configured ADCS, domain-joined Windows 11 clients, and deployed an Ubuntu attacker host — with no public exposure, remote access via encrypted Tailscale mesh
- [**Wazuh EDR Homelab**](Wazuh-Endpoint-Monitoring-Alert-Tuning.md) — Deployed Wazuh as a multi-OS EDR across lab endpoints, enriched telemetry with Sysmon, and tuned custom detection rules mapped to MITRE ATT&CK