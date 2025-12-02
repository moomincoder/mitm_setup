// mitm_setup.go
// By Neko
// This is a tool I wrote that automates the setup of an MitM access point with internet access
// This is for testing the security of IoT devices or other wireless network devices

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// Default TOML config written when no config is present
const defaultConfigTOML = `# mitm_setup default config
ap_iface = "wlx002522446554"
upstream_iface = "wlp1s0"
ap_net = ""
ap_addr = "10.10.10.1"
ap_netmask = "255.255.255.0"
dhcp_range_start = "10.10.10.10"
dhcp_range_end = "10.10.10.200"
ssid = "Lab-MITM-AP"
passphrase = "labpassword"
mitmproxy_port = 8080
dns_port = 53

# Use nftables when available (true/false)
use_nft = true

# Paths to binaries (optional overrides)
hostapd_bin = ""    # e.g. /usr/sbin/hostapd
dnsmasq_bin = ""
tcpdump_bin = ""
mitmdump_bin = ""

# logging verbosity
verbose = true
`

// Config holds TOML-configurable options
type Config struct {
	APIface        string `toml:"ap_iface"`
	UpstreamIface  string `toml:"upstream_iface"`
	APNet          string `toml:"ap_net"`
	APAddr         string `toml:"ap_addr"`
	APNetmask      string `toml:"ap_netmask"`
	DHCPRangeStart string `toml:"dhcp_range_start"`
	DHCPRangeEnd   string `toml:"dhcp_range_end"`
	SSID           string `toml:"ssid"`
	Passphrase     string `toml:"passphrase"`
	Workdir        string `toml:"workdir"`
	MitmproxyPort  int    `toml:"mitmproxy_port"`
	DNSPort        int    `toml:"dns_port"`

	UseNFT    bool   `toml:"use_nft"`

	HostapdBin string `toml:"hostapd_bin"`
	DnsmasqBin string `toml:"dnsmasq_bin"`
	TcpdumpBin string `toml:"tcpdump_bin"`
	MitmdumpBin string `toml:"mitmdump_bin"`

	Verbose bool `toml:"verbose"`
}

var (
	cfgPath string
	cfg     Config
	// Derived
	hostapdConf    string
	dnsmasqConf    string
	mitmproxyLog    string
	pcapFile        string
	iptablesChain   string
	iptablesBackup  string
	sysctlBackup    string
	ipruleFlag     string
	rpfilterDir     string
	pidDir          string
	useNFTAvailable bool
)

func init() {
	flag.StringVar(&cfgPath, "config", "./config.toml", "Path to TOML config file")
}

func main() {
	flag.Parse()
	cmd := ""
	if flag.NArg() > 0 { cmd = flag.Arg(0) }

	if err := loadOrCreateConfig(cfgPath); err != nil { log.Fatalf("config: %v", err) }
	preparePaths()

	// detect nft availability
	if _, err := exec.LookPath("nft"); err == nil && cfg.UseNFT { useNFTAvailable = true }

	// signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Println("signal received: cleaning up")
		stopAll()
		cancel()
		os.Exit(2)
	}()

	switch cmd {
	case "start":
		ensureRoot()
		enforcePrereqs()
		prepareWorkdir()
		if err := chooseDNSPort(); err != nil { log.Fatalf("dns port: %v", err) }
		if err := writeHostapdConf(); err != nil { log.Fatalf("hostapd conf: %v", err) }
		if err := writeDnsmasqConf(); err != nil { log.Fatalf("dnsmasq conf: %v", err) }
		log.Println("Bringing up AP and configuring networking...")
		if err := configureNetworking(); err != nil { log.Fatalf("network: %v", err) }
		if err := addApPolicyBypassRule(); err != nil { log.Fatalf("ip rule: %v", err) }
		if err := chooseMitmPort(); err != nil { log.Fatalf("mitm port: %v", err) }
		if err := setupPacketRedirection(); err != nil { log.Fatalf("firewall: %v", err) }
		if err := startServices(ctx); err != nil { log.Fatalf("services: %v", err) }
		if err := startMitmAndCapture(ctx); err != nil { log.Fatalf("mitm/capture: %v", err) }
		log.Printf("AP up: SSID=%s; mitm port=%d; dns port=%d", cfg.SSID, cfg.MitmproxyPort, cfg.DNSPort)
		showInfo()
	case "stop":
		stopAll()
	case "status":
		showStatus()
	case "info":
		showInfo()
	default:
		printUsage()
		os.Exit(1)
	}
}

// loadOrCreateConfig reads TOML or writes a default
func loadOrCreateConfig(path string) error {
	// if missing, write default
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := ioutil.WriteFile(path, []byte(defaultConfigTOML), 0644); err != nil {
			return fmt.Errorf("unable to write default config to %s: %w", path, err)
		}
		log.Printf("Wrote default config to %s — edit it and re-run if needed", path)
	}
	// decode
	if _, err := toml.DecodeFile(path, &cfg); err != nil { return fmt.Errorf("parsing %s: %w", path, err) }
	// set safe defaults
	if cfg.Passphrase == "" { cfg.Passphrase = "labpassword" }
	// if cfg.Workdir == "" { cfg.Workdir = "/tmp/lab_mitm" }
	if cfg.Workdir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("could not determine current working directory: %w", err)
		}
		cfg.Workdir = cwd
	}
	if cfg.MitmproxyPort == 0 { cfg.MitmproxyPort = 8080 }
	if cfg.DNSPort == 0 { cfg.DNSPort = 53 }
	return nil
}

func preparePaths() {
	hostapdConf = filepath.Join(cfg.Workdir, "hostapd.conf")
	dnsmasqConf = filepath.Join(cfg.Workdir, "dnsmasq.conf")
	mitmproxyLog = filepath.Join(cfg.Workdir, "mitmproxy.log")
	pcapFile = filepath.Join(cfg.Workdir, "captured_traffic.pcap")
	iptablesChain = fmt.Sprintf("MITMCHAIN_%d", os.Getpid())
	iptablesBackup = filepath.Join(cfg.Workdir, "iptables.before")
	sysctlBackup = filepath.Join(cfg.Workdir, "sysctl.before")
	ipruleFlag = filepath.Join(cfg.Workdir, "iprule.added")
	rpfilterDir = filepath.Join(cfg.Workdir, "rpfilter.before")
	pidDir = filepath.Join(cfg.Workdir, "pids")
}

func ensureRoot() {
	if os.Geteuid() != 0 { log.Fatalf("must be run as root (sudo)") }
}

// enforcePrereqs ensures necessary binaries exist or errors with helpful instr
func enforcePrereqs() {
	missing := []string{}
	required := []string{"hostapd", "dnsmasq", "tcpdump", "ip"}
	// mitm can be mitmdump or mitmproxy
	if cfg.MitmdumpBin == "" {
		if _, err := exec.LookPath("mitmdump"); err != nil {
			if _, err2 := exec.LookPath("mitmproxy"); err2 != nil {
				missing = append(missing, "mitmdump|mitmproxy")
			}
		}
	}
	for _, cmd := range required {
		if _, err := exec.LookPath(cmd); err != nil { missing = append(missing, cmd) }
	}
	if len(missing) > 0 {
		log.Fatalf("Missing required commands: %s. On Debian/Ubuntu: sudo apt update && sudo apt install -y hostapd dnsmasq tcpdump mitmproxy iproute2 nftables", strings.Join(missing, ", "))
	}
}

// ----------------- port checks (IPv4 + IPv6) -----------------

func isTCPPortFreeIPv4(port int) bool {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil { return false }
	ln.Close()
	return true
}
func isUDPPortFreeIPv4(port int) bool {
	c, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil { return false }
	c.Close()
	return true
}
func isTCPPortFreeIPv6(port int) bool {
	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: port})
	if err != nil { return false }
	ln.Close()
	return true
}
func isUDPPortFreeIPv6(port int) bool {
	c, err := net.ListenPacket("udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil { return false }
	c.Close()
	return true
}

func isTCPPortFree(port int) bool { return isTCPPortFreeIPv4(port) && isTCPPortFreeIPv6(port) }
func isUDPPortFree(port int) bool { return isUDPPortFreeIPv4(port) && isUDPPortFreeIPv6(port) }

func chooseMitmPort() error {
	base := cfg.MitmproxyPort
	for i := 0; i <= 1000; i++ {
		p := base + i
		if isTCPPortFree(p) { cfg.MitmproxyPort = p; log.Printf("Using mitmproxy port: %d", p); return nil }
	}
	return fmt.Errorf("no free mitmproxy port in %d..%d", base, base+1000)
}

func chooseDNSPort() error {
	if isUDPPortFree(53) && isTCPPortFree(53) { cfg.DNSPort = 53; log.Println("Using DNS port 53"); return nil }
	fallbacks := []int{5353, 5300, 1053, 5354, 5355, 5356, 5357, 5358, 5359, 5360}
	for _, p := range fallbacks { if isUDPPortFree(p) && isTCPPortFree(p) { cfg.DNSPort = p; log.Printf("DNS fallback: %d", p); return nil } }
	return errors.New("no suitable DNS port found")
}

// ----------------- file & conf writes -----------------

func prepareWorkdir() {
	if err := os.MkdirAll(cfg.Workdir, 0700); err != nil { log.Fatalf("workdir: %v", err) }
	if err := os.MkdirAll(rpfilterDir, 0700); err != nil { log.Fatalf("rpfilterDir: %v", err) }
	if err := os.MkdirAll(pidDir, 0700); err != nil { log.Fatalf("pidDir: %v", err) }

	os.Chmod(cfg.Workdir, 0777)
	filepath.Walk(cfg.Workdir, func(path string, info os.FileInfo, err error) error {
	    if err == nil { os.Chmod(path, 0777) }
	    return nil
	})
}

func netmaskToPrefix(mask string) int {
	switch mask {
	case "255.255.255.255": return 32
	case "255.255.255.254": return 31
	case "255.255.255.252": return 30
	case "255.255.255.248": return 29
	case "255.255.255.240": return 28
	case "255.255.255.224": return 27
	case "255.255.255.192": return 26
	case "255.255.255.128": return 25
	case "255.255.255.0":   return 24
	case "255.255.254.0":   return 23
	case "255.255.252.0":   return 22
	case "255.255.248.0":   return 21
	case "255.255.240.0":   return 20
	case "255.255.0.0":     return 16
	case "255.0.0.0":       return 8
	default: return 24
	}
}

func writeHostapdConf() error {
	content := fmt.Sprintf(`interface=%s
driver=nl80211
ssid=%s
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=%s
rsn_pairwise=CCMP
`, cfg.APIface, cfg.SSID, cfg.Passphrase)
	return ioutil.WriteFile(hostapdConf, []byte(content), 0600)
}

func writeDnsmasqConf() error {
	content := fmt.Sprintf(`interface=%s
listen-address=%s
bind-interfaces
port=%d

dhcp-range=%s,%s,%s,12h
# Tell clients their gateway and DNS:
dhcp-option=3,%s
dhcp-option=6,%s
dhcp-authoritative
log-dhcp
log-queries

# Upstream resolvers
server=1.1.1.1
server=8.8.8.8
server=9.9.9.9
no-resolv
cache-size=1000

log-facility=%s/dnsmasq.log
`, cfg.APIface, cfg.APAddr, cfg.DNSPort, cfg.DHCPRangeStart, cfg.DHCPRangeEnd, cfg.APNetmask, cfg.APAddr, cfg.APAddr, cfg.Workdir)
	return ioutil.WriteFile(dnsmasqConf, []byte(content), 0600)
}

// ----------------- sysctl & rp_filter -----------------

func saveSysctlState() {
	log.Printf("Saving sysctl to %s", sysctlBackup)
	f, err := os.Create(sysctlBackup)
	if err != nil { log.Printf("saveSysctl: %v", err); return }
	defer f.Close()
	w := bufio.NewWriter(f)
	if out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output(); err == nil { w.WriteString(fmt.Sprintf("net.ipv4.ip_forward=%s", strings.TrimSpace(string(out)))) }
	ifaces := []string{"all", "default", cfg.APIface, cfg.UpstreamIface}
	for _, ifc := range ifaces {
		if ifc == "" { continue }
		path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifc)
		if b, err := ioutil.ReadFile(path); err == nil { w.WriteString(fmt.Sprintf("net.ipv4.conf.%s.rp_filter=%s", ifc, strings.TrimSpace(string(b)))) }
	}
	w.Flush()
}

func restoreSysctlState() {
	if _, err := os.Stat(sysctlBackup); err != nil { return }
	log.Printf("Restoring sysctl from %s", sysctlBackup)
	f, _ := os.Open(sysctlBackup); defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text(); if line == "" { continue }
		exec.Command("sysctl", "-w", line).Run()
	}
	os.Remove(sysctlBackup)
}

func configureNetworking() error {
	if _, err := exec.Command("ip", "link", "show", "dev", cfg.APIface).Output(); err != nil { return fmt.Errorf("interface %s missing: %w", cfg.APIface, err) }
	exec.Command("ip", "link", "set", "dev", cfg.APIface, "down").Run()
	exec.Command("ip", "addr", "flush", "dev", cfg.APIface).Run()
	prefix := strconv.Itoa(netmaskToPrefix(cfg.APNetmask))
	exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", cfg.APAddr, prefix), "dev", cfg.APIface).Run()
	exec.Command("ip", "link", "set", "dev", cfg.APIface, "up").Run()

	// compute ap_cidr
	var apCIDR string
	if cfg.APNet != "" {
		if strings.Contains(cfg.APNet, "/") { apCIDR = cfg.APNet } else { apCIDR = fmt.Sprintf("%s.0/%s", strings.TrimSuffix(cfg.APNet, "."), prefix) }
	} else {
		parts := strings.Split(cfg.APAddr, "."); if len(parts) >= 3 { apCIDR = fmt.Sprintf("%s.%s.%s.0/%s", parts[0], parts[1], parts[2], prefix) }
	}

	saveSysctlState()
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	ifaces := []string{"all", "default", cfg.APIface, cfg.UpstreamIface}
	for _, ifc := range ifaces {
		if ifc == "" { continue }
		path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifc)
		if b, err := ioutil.ReadFile(path); err == nil {
			ioutil.WriteFile(filepath.Join(rpfilterDir, ifc), b, 0600)
			exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", ifc)).Run()
		}
	}
	ioutil.WriteFile(filepath.Join(cfg.Workdir, "ap_cidr"), []byte(apCIDR), 0600)
	log.Printf("Configured %s -> %s (AP_CIDR=%s)", cfg.APIface, cfg.APAddr, apCIDR)
	return nil
}

func addApPolicyBypassRule() error {
	apcidb, err := ioutil.ReadFile(filepath.Join(cfg.Workdir, "ap_cidr"))
	if err != nil { return fmt.Errorf("AP_CIDR not set; run configureNetworking first") }
	apCIDR := strings.TrimSpace(string(apcidb))
	out, _ := exec.Command("ip", "rule").Output()
	if strings.Contains(string(out), fmt.Sprintf("from %s lookup main", apCIDR)) { log.Printf("ip rule present"); return nil }
	exec.Command("ip", "rule", "add", "from", apCIDR, "lookup", "main", "priority", "100").Run()
	ioutil.WriteFile(ipruleFlag, []byte(fmt.Sprintf("%s 100", apCIDR)), 0600)
	log.Printf("Added ip rule: from %s -> main", apCIDR)
	return nil
}

func removeApPolicyBypassRule() {
	if b, err := ioutil.ReadFile(ipruleFlag); err == nil {
		parts := strings.Fields(string(b)); if len(parts) >= 1 {
			ap := parts[0]
			for {
				out, _ := exec.Command("ip", "rule").Output(); if !strings.Contains(string(out), fmt.Sprintf("from %s lookup main", ap)) { break }
				exec.Command("ip", "rule", "delete", "from", ap, "lookup", "main").Run()
			}
			log.Printf("removed ip rule for %s", ap)
		}
		os.Remove(ipruleFlag)
	}
}

func restoreRpfilterState() {
	files, _ := ioutil.ReadDir(rpfilterDir)
	for _, f := range files {
		b, _ := ioutil.ReadFile(filepath.Join(rpfilterDir, f.Name()))
		exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=%s", f.Name(), strings.TrimSpace(string(b)))).Run()
		os.Remove(filepath.Join(rpfilterDir, f.Name()))
	}
	os.Remove(rpfilterDir)
}

// ----------------- nftables/iptables setup -----------------

func setupPacketRedirection() error {
	// save current nft/iptables state
	if useNFTAvailable {
		return setupNftables()
	}
	return setupIptables()
}

func setupNftables() error {
	log.Println("Using nftables for NAT/redirect rules")
	// attempt to backup existing nft rules
	exec.Command("nft", "list", "ruleset").Run()
	apcidb, _ := ioutil.ReadFile(filepath.Join(cfg.Workdir, "ap_cidr"))
	apcidr := strings.TrimSpace(string(apcidb))
	// create table and chain if missing
	exec.Command("nft", "add", "table", "ip", "nat").Run()
	exec.Command("nft", "add", "chain", "ip", "nat", iptablesChain, "{ type nat hook prerouting priority 0 ; }").Run()
	// flush our chain
	exec.Command("nft", "flush", "chain", "ip", "nat", iptablesChain).Run()
	// redirect http/https to mitm port
	exec.Command("nft", "add", "rule", "ip", "nat", iptablesChain, "iifname", cfg.APIface, "tcp", "dport", "80", "redirect", "to-ports", strconv.Itoa(cfg.MitmproxyPort)).Run()
	exec.Command("nft", "add", "rule", "ip", "nat", iptablesChain, "iifname", cfg.APIface, "tcp", "dport", "443", "redirect", "to-ports", strconv.Itoa(cfg.MitmproxyPort)).Run()
	if cfg.DNSPort != 53 {
		exec.Command("nft", "add", "rule", "ip", "nat", iptablesChain, "iifname", cfg.APIface, "udp", "dport", "53", "redirect", "to-ports", strconv.Itoa(cfg.DNSPort)).Run()
		exec.Command("nft", "add", "rule", "ip", "nat", iptablesChain, "iifname", cfg.APIface, "tcp", "dport", "53", "redirect", "to-ports", strconv.Itoa(cfg.DNSPort)).Run()
	}

	// Create inet filter chains with permissive policy (best-effort, idempotent)
	exec.Command("nft", "add", "table", "inet", "filter").Run()
	exec.Command("nft", "add", "chain", "inet", "filter", "input",
	    "{ type filter hook input priority 0 ; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "inet", "filter", "forward",
	    "{ type filter hook forward priority 0 ; policy accept; }").Run()

	// Allow DHCP/DNS destined to this host on the AP iface
	exec.Command("nft", "add", "rule", "inet", "filter", "input", "iifname", cfg.APIface, "udp", "dport", "67", "accept").Run()
	exec.Command("nft", "add", "rule", "inet", "filter", "input", "iifname", cfg.APIface, "udp", "dport", strconv.Itoa(cfg.DNSPort), "accept").Run()
	exec.Command("nft", "add", "rule", "inet", "filter", "input", "iifname", cfg.APIface, "tcp", "dport", strconv.Itoa(cfg.DNSPort), "accept").Run()

	exec.Command("nft", "add", "table", "inet", "filter").Run()
	exec.Command("nft", "add", "chain", "inet", "filter", "output", "{ type filter hook output priority 0 ; policy accept; }").Run()
	exec.Command("nft", "add", "rule", "inet", "filter", "output", "oifname", cfg.UpstreamIface, "udp", "dport", "53", "accept").Run()
	exec.Command("nft", "add", "rule", "inet", "filter", "output", "oifname", cfg.UpstreamIface, "tcp", "dport", "53", "accept").Run()



	// NAT (masquerade) for upstream
	if cfg.UpstreamIface != "" {
		// add postrouting masquerade
		exec.Command("nft", "add", "chain", "ip", "nat", "postrouting", "{ type nat hook postrouting priority 100 ; }").Run()
		exec.Command("nft", "add", "rule", "ip", "nat", "postrouting", "oifname", cfg.UpstreamIface, "ip", "saddr", apcidr, "counter", "masquerade").Run()
	}
	log.Println("nftables rules added (best-effort)")
	return nil
}

func setupIptables() error {
	log.Println("Using iptables (nft not available)")
	if out, err := exec.Command("iptables-save").Output(); err == nil { ioutil.WriteFile(iptablesBackup, out, 0600) }
	// create or flush chain
	exec.Command("iptables", "-t", "nat", "-N", iptablesChain).Run()
	exec.Command("iptables", "-t", "nat", "-F", iptablesChain).Run()
	// ensure PREROUTING jump
	if err := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING", "-j", iptablesChain).Run(); err != nil {
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-j", iptablesChain).Run()
	}
	// redirect http/https
	exec.Command("iptables", "-t", "nat", "-A", iptablesChain, "-i", cfg.APIface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.MitmproxyPort)).Run()
	exec.Command("iptables", "-t", "nat", "-A", iptablesChain, "-i", cfg.APIface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.MitmproxyPort)).Run()
	if cfg.DNSPort != 53 {
		exec.Command("iptables", "-t", "nat", "-A", iptablesChain, "-i", cfg.APIface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.DNSPort)).Run()
		exec.Command("iptables", "-t", "nat", "-A", iptablesChain, "-i", cfg.APIface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.DNSPort)).Run()
	}
	apcidb, _ := ioutil.ReadFile(filepath.Join(cfg.Workdir, "ap_cidr"))
	apcidr := strings.TrimSpace(string(apcidb))
	if cfg.UpstreamIface != "" {
		exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", apcidr, "-o", cfg.UpstreamIface, "-j", "MASQUERADE").Run()
		exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", apcidr, "-o", cfg.UpstreamIface, "-j", "MASQUERADE").Run()
		exec.Command("iptables", "-I", "FORWARD", "1", "-i", cfg.UpstreamIface, "-o", cfg.APIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
		exec.Command("iptables", "-I", "FORWARD", "1", "-i", cfg.APIface, "-o", cfg.UpstreamIface, "-j", "ACCEPT").Run()
	} else {
		exec.Command("iptables", "-I", "FORWARD", "1", "-i", cfg.APIface, "-o", cfg.APIface, "-j", "ACCEPT").Run()
	}

	// Allow DHCP and DNS to hit this host on the AP iface
	exec.Command("iptables", "-I", "INPUT", "1", "-i", cfg.APIface, "-p", "udp", "--dport", "67", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "INPUT", "1", "-i", cfg.APIface, "-p", "udp", "--dport", strconv.Itoa(cfg.DNSPort), "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "INPUT", "1", "-i", cfg.APIface, "-p", "tcp", "--dport", strconv.Itoa(cfg.DNSPort), "-j", "ACCEPT").Run()

	exec.Command("iptables", "-I", "OUTPUT", "1", "-o", cfg.UpstreamIface, "-p", "udp", "--dport", "53", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "OUTPUT", "1", "-o", cfg.UpstreamIface, "-p", "tcp", "--dport", "53", "-j", "ACCEPT").Run()


	// Also ensure forwarding isn’t dropped elsewhere (defensive)
	exec.Command("iptables", "-I", "FORWARD", "1", "-i", cfg.APIface, "-j", "ACCEPT").Run()

	log.Printf("iptables rules applied (backup saved to %s).", iptablesBackup)
	return nil
}

// ----------------- service management with PID files (no screen) -----------------

func pidPath(name string) string { return filepath.Join(pidDir, name+".pid") }

func writePid(name string, pid int) error { return ioutil.WriteFile(pidPath(name), []byte(strconv.Itoa(pid)), 0644) }
func readPid(name string) (int, error) { b, err := ioutil.ReadFile(pidPath(name)); if err != nil { return 0, err }; return strconv.Atoi(strings.TrimSpace(string(b))) }
func removePid(name string) { os.Remove(pidPath(name)) }

func startServices(ctx context.Context) error {
	// hostapd
	if procAlivePid("hostapd") || procAliveProcname("hostapd") {
		log.Println("hostapd running; reusing")
	} else {
		hostapdPath := cfg.HostapdBin
		if hostapdPath == "" { p, _ := exec.LookPath("hostapd"); hostapdPath = p }
		if hostapdPath == "" { return fmt.Errorf("hostapd not found") }
		logf := filepath.Join(cfg.Workdir, "hostapd.log")
		f, _ := os.OpenFile(logf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		cmd := exec.Command(hostapdPath, hostapdConf)
		cmd.Stdout = f
		cmd.Stderr = f
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil { return fmt.Errorf("failed to start hostapd: %w", err) }
		writePid("hostapd", cmd.Process.Pid)
		time.Sleep(1 * time.Second)
		if !procAliveProcname("hostapd") { stopAll(); return fmt.Errorf("hostapd failed to start") }
		log.Printf("Started hostapd (pid %d); log: %s", cmd.Process.Pid, logf)
	}
	// dnsmasq
	if procAlivePid("dnsmasq") || procAliveProcname("dnsmasq") { log.Println("dnsmasq running; reusing") } else {
		dnsPath := cfg.DnsmasqBin
		if dnsPath == "" { p, _ := exec.LookPath("dnsmasq"); dnsPath = p }
		if dnsPath == "" { stopAll(); return fmt.Errorf("dnsmasq not found") }
		logf := filepath.Join(cfg.Workdir, "dnsmasq.service.log")
		f, _ := os.OpenFile(logf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		cmd := exec.Command(dnsPath, "--conf-file="+dnsmasqConf, "--no-daemon")
		cmd.Stdout = f; cmd.Stderr = f
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil { return fmt.Errorf("dnsmasq failed to start: %w", err) }
		writePid("dnsmasq", cmd.Process.Pid)
		time.Sleep(500 * time.Millisecond)
		if !procAliveProcname("dnsmasq") { printTail(logf, 60); stopAll(); return fmt.Errorf("dnsmasq failed to start") }
		log.Printf("Started dnsmasq (pid %d); logs: %s", cmd.Process.Pid, logf)
	}
	return nil
}

func startMitmAndCapture(ctx context.Context) error {
	mitmPath := cfg.MitmdumpBin
	if mitmPath == "" { if p, err := exec.LookPath("mitmdump"); err == nil { mitmPath = p } else if p2, err2 := exec.LookPath("mitmproxy"); err2 == nil { mitmPath = p2 } }
	if mitmPath == "" { stopAll(); return fmt.Errorf("mitmproxy not found") }
	if err := chooseMitmPort(); err != nil { return err }
	// start mitmproxy with logs
	mitmLog := mitmproxyLog
	f, _ := os.OpenFile(mitmLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	cmd := exec.Command(mitmPath, "--mode", "transparent", "--showhost", "--listen-port", strconv.Itoa(cfg.MitmproxyPort))
	cmd.Stdout = f; cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil { return fmt.Errorf("start mitm: %w", err) }
	writePid("mitmproxy", cmd.Process.Pid)
	time.Sleep(1 * time.Second)
	if !procAlivePid("mitmproxy") && !procAliveProcname("mitmdump") && !procAliveProcname("mitmproxy") { printTail(mitmLog, 60); stopAll(); return fmt.Errorf("mitmproxy failed") }
	log.Printf("Started mitmproxy (pid %d) log: %s", cmd.Process.Pid, mitmLog)

	// tcpdump
	tcpPath := cfg.TcpdumpBin
	if tcpPath == "" { p, _ := exec.LookPath("tcpdump"); tcpPath = p }
	if tcpPath == "" { stopAll(); return fmt.Errorf("tcpdump not found") }
	ioutil.WriteFile(pcapFile, []byte{}, 0600)
	cmd2 := exec.Command(tcpPath, "-i", cfg.APIface, "-w", pcapFile, "-U")
	// tcpdump writes binary pcap, capture stdout only for errors; detach to own pg
	cmd2.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd2.Start(); err != nil { stopAll(); return fmt.Errorf("tcpdump start: %w", err) }
	writePid("tcpdump", cmd2.Process.Pid)
	time.Sleep(500 * time.Millisecond)
	if !procAlivePid("tcpdump") { stopAll(); return fmt.Errorf("tcpdump failed to start") }
	log.Printf("Started tcpdump (pid %d) -> %s", cmd2.Process.Pid, pcapFile)
	return nil
}

func stopAll() {
	log.Println("Stopping services and restoring state...")
	// stop processes using PID files where possible
	stopPidProcess("mitmproxy")
	stopPidProcess("tcpdump")
	stopPidProcess("hostapd")
	stopPidProcess("dnsmasq")
	// fallback best-effort pkill
	exec.Command("pkill", "-f", "mitmproxy|mitmdump").Run()
	exec.Command("pkill", "-f", "tcpdump").Run()
	exec.Command("pkill", "-f", "hostapd").Run()
	exec.Command("pkill", "-f", "dnsmasq").Run()

	removeApPolicyBypassRule()
	// restore firewall
	if useNFTAvailable { // best-effort delete our chains
		exec.Command("nft", "delete", "chain", "ip", "nat", iptablesChain).Run()
		exec.Command("nft", "delete", "chain", "ip", "nat", "postrouting").Run()
	} else {
		if _, err := os.Stat(iptablesBackup); err == nil {
			if out, err := ioutil.ReadFile(iptablesBackup); err == nil {
				cmd := exec.Command("iptables-restore"); cmd.Stdin = strings.NewReader(string(out)); cmd.Run(); log.Printf("Restored iptables from %s", iptablesBackup)
			}
			os.Remove(iptablesBackup)
		} else {
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", iptablesChain).Run()
			exec.Command("iptables", "-t", "nat", "-F", iptablesChain).Run()
			exec.Command("iptables", "-t", "nat", "-X", iptablesChain).Run()
		}
	}

	restoreRpfilterState()
	restoreSysctlState()
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run()
	exec.Command("ip", "link", "set", "dev", cfg.APIface, "down").Run()
	log.Println("Cleanup complete")
}

// ----------------- helpers: process management -----------------

func stopPidProcess(name string) {
	pidf := pidPath(name)
	if b, err := ioutil.ReadFile(pidf); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if pid > 0 {
			// Try graceful termination of the process group
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			time.Sleep(300 * time.Millisecond)
			// If still exists, force
			if processExists(pid) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
		}
		os.Remove(pidf)
	}
}

func procAlivePid(name string) bool { pidf := pidPath(name); if b, err := ioutil.ReadFile(pidf); err == nil { pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); return processExists(pid) }; return false }

func processExists(pid int) bool {
	if pid <= 0 { return false }
	err := syscall.Kill(pid, 0)
	return err == nil
}

func procAliveProcname(prog string) bool {
	out, _ := exec.Command("pgrep", "-f", prog).Output()
	return len(out) > 0
}

func execAvailable(name string) bool { _, err := exec.LookPath(name); return err == nil }

// ----------------- small utilities -----------------

func printTail(path string, lines int) {
	f, err := os.Open(path); if err != nil { return }; defer f.Close()
	stat, _ := f.Stat(); size := stat.Size(); seek := int64(-lines * 200); if -seek > size { seek = -size }
	f.Seek(seek, io.SeekEnd)
	sc := bufio.NewScanner(f); for sc.Scan() { fmt.Println(sc.Text()) }
}

func showStatus() {
	fmt.Println("Processes (pid files):")
	files, _ := ioutil.ReadDir(pidDir)
	for _, f := range files { fmt.Printf("%s", f.Name()) }
	fmt.Println()
	fmt.Printf("PCAP file: %s", pcapFile)
	fmt.Printf("mitmproxy log: %s", mitmproxyLog)
	fmt.Printf("dnsmasq config: %s (port %d)", dnsmasqConf, cfg.DNSPort)
	fmt.Printf("mitmproxy CA: %s", filepath.Join(os.Getenv("HOME"), ".mitmproxy/mitmproxy-ca-cert.pem"))
	fmt.Printf("Current mitmproxy port: %d", cfg.MitmproxyPort)
	if b, err := ioutil.ReadFile(filepath.Join(cfg.Workdir, "ap_cidr")); err == nil { fmt.Printf("AP_CIDR: %s", strings.TrimSpace(string(b))) } else { fmt.Println("AP_CIDR: not-set") }
	if _, err := os.Stat(ipruleFlag); err == nil { fmt.Printf("ap bypass iprule: added (see %s)", ipruleFlag) }
}

func showInfo() {
	fmt.Printf("PCAP file: %s", pcapFile)
	fmt.Printf("mitmproxy CA: %s", filepath.Join(os.Getenv("HOME"), ".mitmproxy/mitmproxy-ca-cert.pem"))
	fmt.Println("To trust mitmproxy on your test device, copy the PEM to the device and install as a trusted CA. Do NOT install this CA on devices you don't control.")
}

func printUsage() { fmt.Printf("Usage: sudo %s start|stop|status|info --config /path/to/config.toml", filepath.Base(os.Args[0])) }
