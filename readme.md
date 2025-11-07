# mitm_setup — Automated MITM Access Point for Testing IoT Devices

mitm_setup is a Go CLI that brings up a lab Wi-Fi access point with DHCP/DNS, transparent mitmproxy, and a tcpdump capture.
For controlled lab testing only. Run as root and only test devices you own or have permission to test.

---

## Features

- Hostapd AP (WPA2-PSK) on a chosen wireless interface
- dnsmasq DHCP/DNS bound to the AP interface
- IP forwarding + rp_filter/ip rule tweaks (saved & restored)
- NAT + redirects (nftables preferred, iptables fallback):
  - HTTP/HTTPS → local mitmproxy (transparent mode)
  - Optional DNS redirect to chosen port
  - Masquerade to upstream interface
- Starts mitmdump/mitmproxy + tcpdump (.pcap written)
- Clean stop & restore on SIGINT/SIGTERM

---

## Prerequisites

Install the following (Debian/Ubuntu example):

sudo apt update
sudo apt install -y hostapd dnsmasq tcpdump mitmproxy iproute2 nftables

Binaries expected (overridable in config):
hostapd, dnsmasq, tcpdump, ip, and one of mitmdump or mitmproxy.
If nft exists and use_nft = true, nftables is used; otherwise iptables.

---

## Build

go build -o mitm_setup mitm_setup.go
or, if in a module:
go install ./...

---

## Quick Start

1) Create or edit a config (a default is auto-written if missing).
2) Start:

sudo ./mitm_setup start --config ./config.toml

3) Stop and clean up:

sudo ./mitm_setup stop --config ./config.toml

4) Status / info:

sudo ./mitm_setup status --config ./config.toml
sudo ./mitm_setup info --config ./config.toml

---

## Configuration (config.toml)

If --config path doesn’t exist, a default is written:

ap_iface = "wlx002522446554"
upstream_iface = "wlp1s0"
ap_net = ""
ap_addr = "10.10.10.1"
ap_netmask = "255.255.255.0"
dhcp_range_start = "10.10.10.10"
dhcp_range_end = "10.10.10.200"
ssid = "Lab-MITM-AP"
passphrase = "labpassword"
workdir = "/tmp/lab_mitm"
mitmproxy_port = 8080
dns_port = 53

use_nft = true

hostapd_bin = ""
dnsmasq_bin = ""
tcpdump_bin = ""
mitmdump_bin = ""

verbose = true

Key fields:
- ap_iface: Wi-Fi interface for AP (must exist and support AP mode)
- upstream_iface: Interface used for internet/NAT (optional)
- ap_addr, ap_netmask: IP/mask on the AP interface (gateway for clients)
- dhcp_range_start, dhcp_range_end: DHCP pool
- ssid, passphrase: AP credentials (WPA2-PSK)
- workdir: Where configs/logs/pcap/PIDs are stored (default /tmp/lab_mitm)
- mitmproxy_port, dns_port: Preferred ports; program will pick a free one if busy
- use_nft: Prefer nftables over iptables when available
- *_bin: Override binary paths if needed
---

## Usage

sudo mitm_setup start|stop|status|info --config /path/to/config.toml

Commands:
- start: checks prereqs, writes configs, configures networking, sets NAT/redirects, starts hostapd, dnsmasq, mitmproxy, tcpdump
- stop: stops processes, restores nft/iptables (best-effort), restores sysctl and rp_filter, downs AP iface
- status: shows running services (via PID files), paths, current ports, AP_CIDR
- info: shows PCAP path and mitmproxy CA location

Example:

sudo ./mitm_setup start --config /etc/mitm_lab/config.toml

---

## Files written (default workdir = /tmp/lab_mitm)

- hostapd.conf, dnsmasq.conf — generated configs
- hostapd.log, dnsmasq.service.log, mitmproxy.log — service logs
- captured_traffic.pcap — tcpdump capture
- pids/*.pid — PIDs for hostapd, dnsmasq, mitmproxy, tcpdump
- iptables.before — iptables backup (when iptables is used)
- sysctl.before — saved sysctl values (e.g., ip_forward, rp_filter)
- rpfilter.before/* — per-interface rp_filter backups
- ap_cidr — computed AP CIDR
- iprule.added — indicates an ip rule was added

---

## How it behaves (important)

- Root required: exits if not run with sudo/root.
- Port selection:
  - DNS: tries 53, then fallbacks (5353, 5300, 1053…)
  - Mitmproxy: tries mitmproxy_port then scans up to +1000
- Routing/filters: adds ip rule from <AP_CIDR> lookup main; disables rp_filter (saved & restored); enables ip_forward; all restored on stop.
- Firewall: nftables chains or iptables rules for:
  - HTTP/HTTPS → REDIRECT to mitmproxy port
  - DNS → REDIRECT if non-53 port in use
  - NAT (masquerade) out upstream_iface

---

## Intercepting HTTPS (mitmproxy CA)

To view TLS traffic from your test device:
1. Start the tool.
2. Copy the mitmproxy CA from the host:
   ~/.mitmproxy/mitmproxy-ca-cert.pem
3. Install that CA on the test device only.
   Never install on production/personal devices.

---

## Example Scenario

Testing an IoT camera:

# config.toml
ap_iface = "wlan1"
upstream_iface = "eth0"
ssid = "Lab-MITM-AP"
passphrase = "supersecret"
ap_addr = "10.10.10.1"
ap_netmask = "255.255.255.0"
dhcp_range_start = "10.10.10.10"
dhcp_range_end = "10.10.10.200"
use_nft = true
workdir = "/tmp/lab_mitm"

Commands:

sudo ./mitm_setup start --config ./config.toml
# let the camera join, use it a bit
sudo ./mitm_setup stop --config ./config.toml

# analyze:
wireshark /tmp/lab_mitm/captured_traffic.pcap
less /tmp/lab_mitm/mitmproxy.log

---

## Troubleshooting

- Missing binaries: installer hint printed on start.
- AP won’t come up: verify ap_iface supports AP mode and isn’t managed by NetworkManager.
- No client internet: set upstream_iface, confirm NAT/masquerade rules, check ap_cidr file.
- Port conflicts: tool auto-chooses free ports; check other daemons.
- Permissions: workdir and files are made permissive; inspect for file creation errors.

---

## Security / Ethics

Use only on devices and networks you control or have explicit permission to test.
Intercepted data may contain sensitive information. Handle responsibly.

---

## License

No warranty. Consider adding a formal license (e.g., MIT) if redistributing.

Author: Neko
