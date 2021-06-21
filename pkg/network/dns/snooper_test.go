// +build linux_bpf

package dns

import (
	"math/rand"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkSnooping(t *testing.T, destIP string, reverseDNS *dnsMonitor) {
	destAddr := util.AddressFromString(destIP)
	srcAddr := util.AddressFromString("127.0.0.1")

	timeout := time.After(1 * time.Second)
Loop:
	// Wait until DNS entry becomes available (with a timeout)
	for {
		select {
		case <-timeout:
			break Loop
		default:
			if reverseDNS.cache.Len() >= 1 {
				break Loop
			}
		}
	}

	// Verify that the IP from the connections above maps to the right name
	payload := []util.Address{srcAddr, destAddr}
	names := reverseDNS.Resolve(payload)
	require.Len(t, names, 1)
	assert.Contains(t, names[destAddr], "golang.org")

	// Verify telemetry
	stats := reverseDNS.GetStats()
	assert.True(t, stats["ips"] >= 1)
	assert.Equal(t, int64(2), stats["lookups"])
	assert.Equal(t, int64(1), stats["resolved"])
}

func TestDNSOverUDPSnooping(t *testing.T) {
	cfg := testConfig()
	cfg.CollectDNSStats = false
	cfg.CollectLocalDNS = false
	cfg.DNSTimeout = 15 * time.Second
	cfg.CollectDNSDomains = false

	reverseDNS, err := NewReverseDNS(cfg)
	require.NoError(t, err)
	defer reverseDNS.Close()

	// Connect to golang.org. This will result in a DNS lookup which will be captured by socketFilterSnooper
	conn, err := net.DialTimeout("tcp", "golang.org:80", 1*time.Second)
	require.NoError(t, err)

	// Get destination IP to compare against snooped DNS
	destIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	conn.Close()
	require.NoError(t, err)

	checkSnooping(t, destIP, reverseDNS.(*dnsMonitor))
}

func TestDNSOverTCPSnooping(t *testing.T) {
	reverseDNS := initDNSTestsWithDomainCollection(t, false)
	defer reverseDNS.Close()

	_, _, reps := sendDNSQueries(t, []string{"golang.org"}, validDNSServerIP, "tcp")
	rep := reps[0]
	require.NotNil(t, rep)
	require.Equal(t, rep.Rcode, mdns.RcodeSuccess)

	for _, r := range rep.Answer {
		aRecord, ok := r.(*mdns.A)
		require.True(t, ok)
		require.True(t, mdns.NumField(aRecord) >= 1)
		destIP := mdns.Field(aRecord, 1)
		checkSnooping(t, destIP, reverseDNS)
	}
}

// Get the preferred outbound IP of this machine
func getOutboundIP(t *testing.T, serverIP string) net.IP {
	if parsedIP := net.ParseIP(serverIP); parsedIP.IsLoopback() {
		return parsedIP
	}
	conn, err := net.Dial("udp", serverIP+":80")
	require.NoError(t, err)
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

const (
	localhost        = "127.0.0.1"
	validDNSServerIP = "8.8.8.8"
)

func initDNSTestsWithDomainCollection(t *testing.T, localDNS bool) *dnsMonitor {
	return initDNSTests(t, localDNS, true)
}

func initDNSTests(t *testing.T, localDNS bool, collectDomain bool) *dnsMonitor {
	cfg := testConfig()
	cfg.CollectDNSStats = true
	cfg.CollectLocalDNS = localDNS
	cfg.DNSTimeout = 1 * time.Second
	cfg.CollectDNSDomains = collectDomain

	rdns, err := NewReverseDNS(cfg)
	require.NoError(t, err)

	return rdns.(*dnsMonitor)
}

func sendDNSQueries(
	t *testing.T,
	domains []string,
	serverIP string,
	protocol string,
) (string, int, []*mdns.Msg) {
	// Create a DNS query message
	msg := new(mdns.Msg)
	msg.RecursionDesired = true
	queryIP := getOutboundIP(t, serverIP).String()

	rand.Seed(time.Now().UnixNano())
	queryPort := rand.Intn(20000) + 10000

	var dnsClientAddr net.Addr
	if protocol == "tcp" {
		dnsClientAddr = &net.TCPAddr{IP: net.ParseIP(queryIP), Port: queryPort}
	} else {
		dnsClientAddr = &net.UDPAddr{IP: net.ParseIP(queryIP), Port: queryPort}
	}

	localAddrDialer := &net.Dialer{
		LocalAddr: dnsClientAddr,
		Timeout:   5 * time.Second,
	}

	dnsClient := mdns.Client{Net: protocol, Dialer: localAddrDialer}
	dnsHost := net.JoinHostPort(serverIP, "53")
	var reps []*mdns.Msg

	if protocol == "tcp" {
		conn, err := dnsClient.Dial(dnsHost)
		require.NoError(t, err)
		for _, domain := range domains {
			msg.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
			rep, _, _ := dnsClient.ExchangeWithConn(msg, conn)
			reps = append(reps, rep)
		}
	} else { // UDP
		for _, domain := range domains {
			msg.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
			rep, _, _ := dnsClient.Exchange(msg, dnsHost)
			reps = append(reps, rep)
		}
	}
	return queryIP, queryPort, reps
}

func getKey(
	qIP string,
	qPort int,
	sIP string,
	protocol uint8,
) Key {
	return Key{
		ClientIP:   util.AddressFromString(qIP),
		ClientPort: uint16(qPort),
		ServerIP:   util.AddressFromString(sIP),
		Protocol:   protocol,
	}
}

func hasDomains(stats map[string]Stats, domains ...string) bool {
	for _, domain := range domains {
		if _, ok := stats[domain]; !ok {
			return false
		}
	}

	return true
}

func countDNSResponses(stats map[Key]map[string]Stats) int {
	total := 0
	for _, statsByDomain := range stats {
		for _, s := range statsByDomain {
			total += int(s.Timeouts)
			for _, count := range s.CountByRcode {
				total += int(count)
			}
		}
	}
	return total
}

func TestDNSOverTCPSuccessfulResponseCountWithoutDomain(t *testing.T) {
	reverseDNS := initDNSTests(t, false, false)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper
	domains := []string{
		"golang.org",
		"google.com",
		"acm.org",
	}
	queryIP, queryPort, reps := sendDNSQueries(t, domains, validDNSServerIP, "tcp")

	// Check that all the queries succeeded
	for _, rep := range reps {
		require.NotNil(t, rep)
		require.Equal(t, rep.Rcode, mdns.RcodeSuccess)
	}

	key := getKey(queryIP, queryPort, validDNSServerIP, syscall.IPPROTO_TCP)
	var allStats map[Key]map[string]Stats
	require.Eventuallyf(t, func() bool {
		allStats = statKeeper.Snapshot()
		return allStats[key] != nil && countDNSResponses(allStats) >= len(domains)
	}, 3*time.Second, 10*time.Millisecond, "not enough DNS responses")

	// Exactly one rcode (0, success) is expected
	stats := allStats[key][""]
	require.Equal(t, 1, len(stats.CountByRcode))
	assert.Equal(t, uint32(3), stats.CountByRcode[uint32(layers.DNSResponseCodeNoErr)])
	assert.True(t, stats.SuccessLatencySum >= uint64(1))
	assert.Equal(t, uint32(0), stats.Timeouts)
	assert.Equal(t, uint64(0), stats.FailureLatencySum)
}

func TestDNSOverTCPSuccessfulResponseCount(t *testing.T) {
	reverseDNS := initDNSTestsWithDomainCollection(t, false)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper
	domains := []string{
		"golang.org",
		"google.com",
		"acm.org",
	}
	queryIP, queryPort, reps := sendDNSQueries(t, domains, validDNSServerIP, "tcp")

	// Check that all the queries succeeded
	for _, rep := range reps {
		require.NotNil(t, rep)
		require.Equal(t, rep.Rcode, mdns.RcodeSuccess)
	}

	var allStats map[Key]map[string]Stats
	key := getKey(queryIP, queryPort, validDNSServerIP, syscall.IPPROTO_TCP)
	require.Eventually(t, func() bool {
		allStats = statKeeper.Snapshot()
		return hasDomains(allStats[key], domains...)
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for domains %+v", domains)

	// Exactly one rcode (0, success) is expected
	for _, d := range domains {
		stats := allStats[key][d]
		require.Equal(t, 1, len(stats.CountByRcode))
		assert.Equal(t, uint32(1), stats.CountByRcode[uint32(layers.DNSResponseCodeNoErr)])
		assert.True(t, stats.SuccessLatencySum >= uint64(1))
		assert.Equal(t, uint32(0), stats.Timeouts)
		assert.Equal(t, uint64(0), stats.FailureLatencySum)
	}
}

type handler struct{}

func (h *handler) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	msg := mdns.Msg{}
	msg.SetReply(r)
	msg.SetRcode(r, mdns.RcodeServerFailure)
	_ = w.WriteMsg(&msg)
}

func TestDNSFailedResponseCount(t *testing.T) {
	reverseDNS := initDNSTestsWithDomainCollection(t, true)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper

	domains := []string{
		"nonexistenent.com.net",
		"aabdgdfsgsdafsdafsad",
	}
	queryIP, queryPort, reps := sendDNSQueries(t, domains, validDNSServerIP, "tcp")
	for _, rep := range reps {
		require.NotNil(t, rep)
		require.NotEqual(t, rep.Rcode, mdns.RcodeSuccess) // All the queries should have failed
	}
	key1 := getKey(queryIP, queryPort, validDNSServerIP, syscall.IPPROTO_TCP)

	// Set up a local DNS server to return SERVFAIL
	localServerAddr := &net.UDPAddr{IP: net.ParseIP(localhost), Port: 53}
	localServer := &mdns.Server{Addr: localServerAddr.String(), Net: "udp"}
	localServer.Handler = &handler{}
	waitLock := sync.Mutex{}
	waitLock.Lock()
	localServer.NotifyStartedFunc = waitLock.Unlock
	defer localServer.Shutdown()

	go func() {
		if err := localServer.ListenAndServe(); err != nil {
			t.Fatalf("Failed to set listener %s\n", err.Error())
		}
	}()
	waitLock.Lock()
	queryIP, queryPort, _ = sendDNSQueries(t, domains, localhost, "udp")
	var allStats map[Key]map[string]Stats

	// First check the one sent over TCP. Expected error type: NXDomain
	require.Eventually(t, func() bool {
		allStats = statKeeper.Snapshot()
		return hasDomains(allStats[key1], domains...)
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for TCP requests")
	for _, d := range domains {
		require.Equal(t, 1, len(allStats[key1][d].CountByRcode))
		assert.Equal(t, uint32(1), allStats[key1][d].CountByRcode[uint32(layers.DNSResponseCodeNXDomain)], "expected one NXDOMAIN for %s, got %v", d, allStats[key1][d])
	}

	// Next check the one sent over UDP. Expected error type: ServFail
	key2 := getKey(queryIP, queryPort, localhost, syscall.IPPROTO_UDP)
	require.Eventually(t, func() bool {
		allStats = statKeeper.Snapshot()
		return hasDomains(allStats[key2], domains...)
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for UDP requests")
	for _, d := range domains {
		require.Equal(t, 1, len(allStats[key2][d].CountByRcode))
		assert.Equal(t, uint32(1), allStats[key2][d].CountByRcode[uint32(layers.DNSResponseCodeServFail)])
	}
}

func TestDNSOverUDPTimeoutCount(t *testing.T) {
	reverseDNS := initDNSTestsWithDomainCollection(t, false)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper

	invalidServerIP := "8.8.8.90"
	domainQueried := "agafsdfsdasdfsd"
	queryIP, queryPort, reps := sendDNSQueries(t, []string{domainQueried}, invalidServerIP, "udp")
	require.Nil(t, reps[0])

	var allStats map[Key]map[string]Stats
	key := getKey(queryIP, queryPort, invalidServerIP, syscall.IPPROTO_UDP)
	require.Eventually(t, func() bool {
		allStats = statKeeper.Snapshot()
		return allStats[key] != nil
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for key %v", key)
	assert.Equal(t, 0, len(allStats[key][domainQueried].CountByRcode))
	assert.Equal(t, uint32(1), allStats[key][domainQueried].Timeouts)
	assert.Equal(t, uint64(0), allStats[key][domainQueried].SuccessLatencySum)
	assert.Equal(t, uint64(0), allStats[key][domainQueried].FailureLatencySum)
}

func TestDNSOverUDPTimeoutCountWithoutDomain(t *testing.T) {
	reverseDNS := initDNSTests(t, false, false)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper

	invalidServerIP := "8.8.8.90"
	domainQueried := "agafsdfsdasdfsd"
	queryIP, queryPort, reps := sendDNSQueries(t, []string{domainQueried}, invalidServerIP, "udp")
	require.Nil(t, reps[0])

	key := getKey(queryIP, queryPort, invalidServerIP, syscall.IPPROTO_UDP)
	var allStats map[Key]map[string]Stats
	require.Eventuallyf(t, func() bool {
		allStats = statKeeper.Snapshot()
		return allStats[key] != nil
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for key %v", key)

	assert.Equal(t, 0, len(allStats[key][""].CountByRcode))
	assert.Equal(t, uint32(1), allStats[key][""].Timeouts)
	assert.Equal(t, uint64(0), allStats[key][""].SuccessLatencySum)
	assert.Equal(t, uint64(0), allStats[key][""].FailureLatencySum)
}

func TestParsingError(t *testing.T) {
	cfg := testConfig()
	cfg.CollectDNSStats = false
	cfg.CollectLocalDNS = false
	cfg.CollectDNSDomains = false
	cfg.DNSTimeout = 15 * time.Second
	rdns, err := NewReverseDNS(cfg)
	require.NoError(t, err)
	defer rdns.Close()

	reverseDNS := rdns.(*dnsMonitor)
	// Pass a byte array of size 1 which should result in parsing error
	err = reverseDNS.processPacket(make([]byte, 1), time.Now())
	require.NoError(t, err)
	stats := reverseDNS.GetStats()
	assert.True(t, stats["ips"] == 0)
	assert.True(t, stats["decoding_errors"] == 1)
}

func TestDNSOverIPv6(t *testing.T) {
	reverseDNS := initDNSTestsWithDomainCollection(t, true)
	defer reverseDNS.Close()
	statKeeper := reverseDNS.statKeeper

	// This DNS server is set up so it always returns a NXDOMAIN answer
	serverIP := net.IPv6loopback.String()
	closeFn := newTestServer(t, serverIP, "udp", nxDomainHandler)
	defer closeFn()

	queryIP, queryPort, reps := sendDNSQueries(t, []string{"nxdomain-123.com"}, serverIP, "udp")
	require.NotNil(t, reps[0])

	key := getKey(queryIP, queryPort, serverIP, syscall.IPPROTO_UDP)
	var allStats map[Key]map[string]Stats
	require.Eventually(t, func() bool {
		allStats = statKeeper.Snapshot()
		return allStats[key] != nil
	}, 3*time.Second, 10*time.Millisecond, "missing DNS data for key %v", key)

	stats := allStats[key]["nxdomain-123.com"]
	assert.Equal(t, 1, len(stats.CountByRcode))
	assert.Equal(t, uint32(1), stats.CountByRcode[uint32(layers.DNSResponseCodeNXDomain)])
}

func newTestServer(t *testing.T, ip string, protocol string, handler dns.HandlerFunc) func() {
	addr := net.JoinHostPort(ip, "53")
	srv := &dns.Server{Addr: addr, Net: protocol, Handler: handler}

	initChan := make(chan error, 1)
	srv.NotifyStartedFunc = func() {
		initChan <- nil
	}

	go func() {
		initChan <- srv.ListenAndServe()
		close(initChan)
	}()

	if err := <-initChan; err != nil {
		t.Errorf("could not initialize DNS server: %s", err)
		return func() {}
	}

	return func() {
		srv.Shutdown() //nolint:errcheck
	}
}

// nxDomainHandler returns a NXDOMAIN response for any query
func nxDomainHandler(w dns.ResponseWriter, r *dns.Msg) {
	answer := new(dns.Msg)
	answer.SetReply(r)
	answer.SetRcode(r, dns.RcodeNameError)
	w.WriteMsg(answer) //nolint:errcheck
}

func testConfig() *config.Config {
	return config.New()
}
