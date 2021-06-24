//+build linux_bpf

package tracer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/network/netlink"
	"github.com/DataDog/datadog-agent/pkg/process/util"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/config/sysctl"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/ebpf"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnetns "github.com/vishvananda/netns"
)

func dnsSupported(t *testing.T) bool {
	currKernelVersion, err := kernel.HostVersion()
	require.NoError(t, err)
	return currKernelVersion < kernel.VersionCode(4, 1, 0)
}

func httpSupported(t *testing.T) bool {
	currKernelVersion, err := kernel.HostVersion()
	require.NoError(t, err)
	return currKernelVersion < kernel.VersionCode(4, 1, 0)
}

func connectionBufferCapacity(t *Tracer) int {
	return cap(t.buffer)
}

func TestTCPRemoveEntries(t *testing.T) {
	config := testConfig()
	config.TCPConnTimeout = 100 * time.Millisecond
	tr, err := NewTracer(config)
	require.NoError(t, err)
	defer tr.Stop()

	// Create a dummy TCP Server
	server := NewTCPServer(func(c net.Conn) {
		c.Close()
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, 2*time.Second)
	require.NoError(t, err)

	// Write a message
	_, err = c.Write(genPayload(clientMessageSize))
	require.NoError(t, err)
	defer c.Close()

	// Write a bunch of messages with blocking iptable rule to create retransmits
	iptablesWrapper(t, func() {
		for i := 0; i < 99; i++ {
			// Send a bunch of messages
			c.Write(genPayload(clientMessageSize))
		}
		time.Sleep(time.Second)
	})

	// Wait a bit for the first connection to be considered as timeouting
	time.Sleep(1 * time.Second)

	// Create a new client
	c2, err := net.DialTimeout("tcp", server.address, 1*time.Second)
	require.NoError(t, err)

	// Send a messages
	_, err = c2.Write(genPayload(clientMessageSize))
	require.NoError(t, err)
	defer c2.Close()

	c.Close()
	// Retrieve the list of connections
	connections := getConnections(t, tr)

	// Make sure the first connection got cleaned up
	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	// Assert the TCP map does not contain first connection because of the clean up
	tcpMp, err := tr.getMap(probes.TcpStatsMap)
	require.NoError(t, err)

	key, err := connTupleFromConn(c, 0, 0)
	require.NoError(t, err)
	stats := new(TCPStats)
	err = tcpMp.Lookup(unsafe.Pointer(key), unsafe.Pointer(stats))
	if !assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist)) {
		t.Logf("tcp_stats map entries:\n")
		ek := &ConnTuple{}
		sv := new(TCPStats)
		entries := tcpMp.IterateFrom(unsafe.Pointer(&ConnTuple{}))
		for entries.Next(unsafe.Pointer(ek), unsafe.Pointer(sv)) {
			t.Logf("%s => %+v\n", ek, sv)
		}
		require.NoError(t, entries.Err())
	}

	conn, ok := findConnection(c2.LocalAddr(), c2.RemoteAddr(), connections)
	require.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.MonotonicSentBytes))
	assert.Equal(t, 0, int(conn.MonotonicRecvBytes))
	assert.Equal(t, 0, int(conn.MonotonicRetransmits))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))
}

func TestTCPRetransmitSharedSocket(t *testing.T) {
	// Enable BPF-based system probe
	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	// Create TCP Server that simply "drains" connection until receiving an EOF
	server := NewTCPServer(func(c net.Conn) {
		io.Copy(ioutil.Discard, c)
		c.Close()
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, time.Second)
	require.NoError(t, err)
	socketFile, err := c.(*net.TCPConn).File()
	require.NoError(t, err)
	const numProcesses = 10
	iptablesWrapper(t, func() {
		for i := 0; i < numProcesses; i++ {
			// Establish one connection per process, all sharing the same socket represented by fd=3
			// https://github.com/golang/go/blob/release-branch.go1.10/src/os/exec/exec.go#L111-L114
			msg := genPayload(clientMessageSize)
			cmd := exec.Command("bash", "-c", fmt.Sprintf("echo -ne %q >&3", msg))
			cmd.ExtraFiles = []*os.File{socketFile}
			err := cmd.Run()
			require.NoError(t, err)
		}
		time.Sleep(time.Second)
	})
	socketFile.Close()
	c.Close()

	// Fetch all connections matching source and target address
	allConnections := getConnections(t, tr)
	conns := searchConnections(allConnections, byAddress(c.LocalAddr(), c.RemoteAddr()))
	require.Len(t, conns, numProcesses)

	totalSent := 0
	for _, c := range conns {
		totalSent += int(c.MonotonicSentBytes)
	}
	assert.Equal(t, numProcesses*clientMessageSize, totalSent)

	// Since we can't reliably identify the PID associated to a retransmit, we have opted
	// to report the total number of retransmits for *one* of the connections sharing the
	// same socket
	connsWithRetransmits := 0
	for _, c := range conns {
		if c.MonotonicRetransmits > 0 {
			connsWithRetransmits++
		}
	}
	assert.Equal(t, 1, connsWithRetransmits)

	// Test if telemetry measuring PID collisions is correct
	// >= because there can be other connections going on during CI that increase pidCollisions
	assert.GreaterOrEqual(t, atomic.LoadInt64(&tr.pidCollisions), int64(numProcesses-1))
}

func TestTCPRTT(t *testing.T) {
	// Enable BPF-based system probe
	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	// Create TCP Server that simply "drains" connection until receiving an EOF
	server := NewTCPServer(func(c net.Conn) {
		io.Copy(ioutil.Discard, c)
		c.Close()
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	c, err := net.DialTimeout("tcp", server.address, time.Second)
	require.NoError(t, err)
	defer c.Close()

	// Wait for a second so RTT can stabilize
	time.Sleep(1 * time.Second)

	// Obtain information from a TCP socket via GETSOCKOPT(2) system call.
	tcpInfo, err := tcpGetInfo(c)
	require.NoError(t, err)

	// Write something to socket to ensure connection is tracked
	// This will trigger the collection of TCP stats including RTT
	_, err = c.Write([]byte("foo"))
	require.NoError(t, err)

	// Fetch connection matching source and target address
	allConnections := getConnections(t, tr)
	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), allConnections)
	require.True(t, ok)

	// Assert that values returned from syscall match ones generated by eBPF program
	assert.EqualValues(t, int(tcpInfo.Rtt), int(conn.RTT))
	assert.EqualValues(t, int(tcpInfo.Rttvar), int(conn.RTTVar))
}

func TestIsExpired(t *testing.T) {
	// 10mn
	var timeout uint64 = 600000000000
	for _, tc := range []struct {
		stats      ConnStatsWithTimestamp
		latestTime uint64
		expected   bool
	}{
		{
			ConnStatsWithTimestamp{timestamp: 101},
			100,
			false,
		},
		{
			ConnStatsWithTimestamp{timestamp: 100},
			101,
			false,
		},
		{
			ConnStatsWithTimestamp{timestamp: 100},
			101 + timeout,
			true,
		},
	} {
		assert.Equal(t, tc.expected, tc.stats.isExpired(tc.latestTime, timeout))
	}
}

func TestTCPMiscount(t *testing.T) {
	t.Skip("skipping because this test will pass/fail depending on host performance")
	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	// Create a dummy TCP Server
	server := NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			if _, err := r.ReadBytes(byte('\n')); err != nil { // indicates that EOF has been reached,
				break
			}
		}
		c.Close()
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	file, err := c.(*net.TCPConn).File()
	require.NoError(t, err)

	fd := int(file.Fd())

	// Set a really low sendtimeout of 1us to trigger EAGAIN errors in `tcp_sendmsg`
	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &syscall.Timeval{
		Sec:  0,
		Usec: 1,
	})
	require.NoError(t, err)

	// 100 MB payload
	x := make([]byte, 100*1024*1024)

	n, err := c.Write(x)
	assert.NoError(t, err)
	assert.EqualValues(t, len(x), n)

	doneChan <- struct{}{}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), getConnections(t, tr))
	assert.True(t, ok)

	// TODO this should not happen but is expected for now
	// we don't have the correct count since retries happened
	assert.False(t, uint64(len(x)) == conn.MonotonicSentBytes)

	tel := tr.getEbpfTelemetry()
	assert.NotZero(t, tel["tcp_sent_miscounts"])
}

func TestConnectionExpirationRegression(t *testing.T) {
	t.SkipNow()
	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	// Create TCP Server that simply "drains" connection until receiving an EOF
	connClosed := make(chan struct{})
	server := NewTCPServer(func(c net.Conn) {
		io.Copy(ioutil.Discard, c)
		c.Close()
		connClosed <- struct{}{}
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	c, err := net.DialTimeout("tcp", server.address, time.Second)
	require.NoError(t, err)

	// Warm up state
	_ = getConnections(t, tr)

	// Write 5 bytes to TCP socket
	payload := []byte("12345")
	_, err = c.Write(payload)
	require.NoError(t, err)

	// Fetch connection matching source and target address
	// This will make sure to populate the state for this particular client
	allConnections := getConnections(t, tr)
	connectionStats, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), allConnections)
	require.True(t, ok)
	assert.Equal(t, uint64(len(payload)), connectionStats.LastSentBytes)

	// This emulates the race condition, a `tcp_close` followed by a call to `Tracer.removeConnections()`
	// It's unfortunate we're relying here on private methods, but there isn't much we can do to avoid that.
	c.Close()
	<-connClosed
	time.Sleep(100 * time.Millisecond)
	removeConnection(t, tr, connectionStats)

	// Since no bytes were send or received after we obtained the connectionStats, we should have 0 LastBytesSent
	allConnections = getConnections(t, tr)
	connectionStats, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), allConnections)
	require.True(t, ok)
	assert.Equal(t, uint64(0), connectionStats.LastSentBytes)

	// Finally, this connection should have been expired from the state
	allConnections = getConnections(t, tr)
	_, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), allConnections)
	require.False(t, ok)
}

func removeConnection(t *testing.T, tr *Tracer, c *network.ConnectionStats) {
	mp, err := tr.getMap(probes.ConnMap)
	require.NoError(t, err)

	tcpMp, err := tr.getMap(probes.TcpStatsMap)
	require.NoError(t, err)

	tuple := []*ConnTuple{
		{
			pid:      _Ctype_uint(c.Pid),
			saddr_l:  _Ctype_ulonglong(nativeEndian.Uint32(c.Source.Bytes())),
			daddr_l:  _Ctype_ulonglong(nativeEndian.Uint32(c.Dest.Bytes())),
			sport:    _Ctype_ushort(c.SPort),
			dport:    _Ctype_ushort(c.DPort),
			netns:    _Ctype_uint(c.NetNS),
			metadata: 1, // TCP/IPv4
		},
	}

	tr.removeEntries(mp, tcpMp, tuple)
}

func TestConntrackExpiration(t *testing.T) {
	setupDNAT(t)
	defer teardownDNAT(t)

	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	// Warm-up tracer state
	_ = getConnections(t, tr)

	// The random port is necessary to avoid flakiness in the test. Running the the test multiple
	// times can fail if binding to the same port since Conntrack might not emit NEW events for the same tuple
	rand.Seed(time.Now().UnixNano())
	port := 5430 + rand.Intn(100)
	server := NewTCPServerOnAddress(fmt.Sprintf("1.1.1.1:%d", port), func(c net.Conn) {
		io.Copy(ioutil.Discard, c)
		c.Close()
	})
	doneChan := make(chan struct{})
	err = server.Run(doneChan)
	require.NoError(t, err)
	defer close(doneChan)

	c, err := net.Dial("tcp", fmt.Sprintf("2.2.2.2:%d", port))
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("ping"))
	require.NoError(t, err)

	// Give enough time for conntrack cache to be populated
	time.Sleep(100 * time.Millisecond)

	connections := getConnections(t, tr)
	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	require.True(t, ok)
	require.NotNil(t, tr.conntracker.GetTranslationForConn(*conn), "missing translation for connection")

	// This will force the connection to be expired next time we call getConnections, but
	// conntrack should still have the connection information since the connection is still
	// alive
	tr.config.TCPConnTimeout = time.Duration(-1)
	_ = getConnections(t, tr)

	assert.NotNil(t, tr.conntracker.GetTranslationForConn(*conn), "translation should not have been deleted")

	// delete the connection from system conntrack
	cmd := exec.Command("conntrack", "-D", "-s", c.LocalAddr().(*net.TCPAddr).IP.String(), "-d", c.RemoteAddr().(*net.TCPAddr).IP.String(), "-p", "tcp")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "conntrack delete failed, output: %s", out)
	_ = getConnections(t, tr)

	assert.Nil(t, tr.conntracker.GetTranslationForConn(*conn), "translation should have been deleted")
}

func TestUnconnectedUDPSendIPv6(t *testing.T) {
	if !kernel.IsIPv6Enabled() {
		t.Skip("IPv6 not enabled on host")
	}

	cfg := testConfig()
	cfg.CollectIPv6Conns = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	defer tr.Stop()

	linkLocal, err := getIPv6LinkLocalAddress()
	require.NoError(t, err)

	remotePort := rand.Int()%5000 + 15000
	remoteAddr := &net.UDPAddr{IP: net.ParseIP(interfaceLocalMulticastIPv6), Port: remotePort}
	conn, err := net.ListenUDP("udp6", linkLocal)
	require.NoError(t, err)
	defer conn.Close()
	message := []byte("payload")
	bytesSent, err := conn.WriteTo(message, remoteAddr)
	require.NoError(t, err)

	connections := getConnections(t, tr)
	outgoing := searchConnections(connections, func(cs network.ConnectionStats) bool {
		return cs.DPort == uint16(remotePort)
	})

	require.Len(t, outgoing, 1)
	assert.Equal(t, remoteAddr.IP.String(), outgoing[0].Dest.String())
	assert.Equal(t, bytesSent, int(outgoing[0].MonotonicSentBytes))
}

func TestGatewayLookupNotEnabled(t *testing.T) {
	t.Run("gateway lookup not enabled", func(t *testing.T) {
		cfg := testConfig()
		tr, err := NewTracer(cfg)
		require.NoError(t, err)
		require.NotNil(t, tr)
		defer tr.Stop()
		require.Nil(t, tr.gwLookup)
	})

	t.Run("gateway lookup enabled, not on aws", func(t *testing.T) {
		cfg := testConfig()
		cfg.EnableGatewayLookup = true
		oldCloud := cloud
		defer func() {
			cloud = oldCloud
		}()
		ctrl := gomock.NewController(t)
		m := NewMockcloudProvider(ctrl)
		m.EXPECT().IsAWS().Return(false)
		cloud = m
		tr, err := NewTracer(cfg)
		require.NoError(t, err)
		require.NotNil(t, tr)
		defer tr.Stop()
		require.Nil(t, tr.gwLookup)
	})

	t.Run("gateway lookup enabled, aws metadata endpoint not enabled", func(t *testing.T) {
		cfg := testConfig()
		cfg.EnableGatewayLookup = true
		oldCloud := cloud
		defer func() {
			cloud = oldCloud
		}()
		ctrl := gomock.NewController(t)
		m := NewMockcloudProvider(ctrl)
		m.EXPECT().IsAWS().Return(true)
		cloud = m

		clouds := ddconfig.Datadog.Get("cloud_provider_metadata")
		ddconfig.Datadog.Set("cloud_provider_metadata", []string{})
		defer ddconfig.Datadog.Set("cloud_provider_metadata", clouds)

		tr, err := NewTracer(cfg)
		require.NoError(t, err)
		require.NotNil(t, tr)
		defer tr.Stop()
		require.Nil(t, tr.gwLookup)
	})
}

func TestGatewayLookupEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := NewMockcloudProvider(ctrl)
	oldCloud := cloud
	defer func() {
		cloud = oldCloud
	}()

	m.EXPECT().IsAWS().Return(true)
	cloud = m

	cfg := testConfig()
	cfg.BPFDebug = true
	cfg.EnableGatewayLookup = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Stop()

	require.NotNil(t, tr.gwLookup)

	ifi := ipRouteGet(t, "", "8.8.8.8", nil)
	ifs, err := net.Interfaces()
	require.NoError(t, err)
	tr.gwLookup.subnetForHwAddrFunc = func(hwAddr net.HardwareAddr) (network.Subnet, error) {
		for _, i := range ifs {
			if hwAddr.String() == i.HardwareAddr.String() {
				return network.Subnet{Alias: fmt.Sprintf("subnet-%d", i.Index)}, nil
			}
		}

		return network.Subnet{Alias: "subnet"}, nil
	}

	getConnections(t, tr)

	dnsClientAddr, dnsServerAddr := doDNSQuery(t, "google.com", "8.8.8.8")

	var conn *network.ConnectionStats
	require.Eventually(t, func() bool {
		var ok bool
		conn, ok = findConnection(dnsClientAddr, dnsServerAddr, getConnections(t, tr))
		return ok
	}, 2*time.Second, time.Second)

	require.NotNil(t, conn.Via)
	require.Equal(t, conn.Via.Subnet.Alias, fmt.Sprintf("subnet-%d", ifi.Index))
}

func TestGatewayLookupSubnetLookupError(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := NewMockcloudProvider(ctrl)
	oldCloud := cloud
	defer func() {
		cloud = oldCloud
	}()

	m.EXPECT().IsAWS().Return(true)
	cloud = m

	cfg := testConfig()
	cfg.BPFDebug = true
	cfg.EnableGatewayLookup = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Stop()

	require.NotNil(t, tr.gwLookup)

	ifi := ipRouteGet(t, "", "8.8.8.8", nil)
	calls := 0
	tr.gwLookup.subnetForHwAddrFunc = func(hwAddr net.HardwareAddr) (network.Subnet, error) {
		if hwAddr.String() == ifi.HardwareAddr.String() {
			calls++
		}
		return network.Subnet{}, assert.AnError
	}

	tr.gwLookup.purge()

	getConnections(t, tr)

	// do two dns queries to prompt more than one subnet lookup attempt
	localAddr, remoteAddr := doDNSQuery(t, "google.com", "8.8.8.8")
	var c *network.ConnectionStats
	require.Eventually(t, func() bool {
		var ok bool
		c, ok = findConnection(localAddr, remoteAddr, getConnections(t, tr))
		return ok
	}, 3*time.Second, 500*time.Millisecond, "connection not found")
	require.Nil(t, c.Via)

	localAddr, remoteAddr = doDNSQuery(t, "google.com", "8.8.8.8")
	require.Eventually(t, func() bool {
		var ok bool
		c, ok = findConnection(localAddr, remoteAddr, getConnections(t, tr))
		return ok
	}, 3*time.Second, 500*time.Millisecond, "connection not found")
	require.Nil(t, c.Via)

	require.Equal(t, 1, calls, "calls to subnetForHwAddrFunc are != 1 for hw addr %s", ifi.HardwareAddr)
}

func TestGatewayLookupCrossNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := NewMockcloudProvider(ctrl)
	oldCloud := cloud
	defer func() {
		cloud = oldCloud
	}()

	m.EXPECT().IsAWS().Return(true)
	cloud = m

	cfg := testConfig()
	cfg.BPFDebug = true
	cfg.EnableGatewayLookup = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Stop()

	require.NotNil(t, tr.gwLookup)
	// setup two network namespaces
	cmds := []string{
		"ip link add br0 type bridge",
		"ip addr add 2.2.2.1/24 broadcast 2.2.2.255 dev br0",
		"ip netns add test1",
		"ip netns add test2",
		"ip link add veth1 type veth peer name veth2",
		"ip link set veth1 master br0",
		"ip link set veth2 netns test1",
		"ip -n test1 addr add 2.2.2.2/24 broadcast 2.2.2.255 dev veth2",
		"ip link add veth3 type veth peer name veth4",
		"ip link set veth3 master br0",
		"ip link set veth4 netns test2",
		"ip -n test2 addr add 2.2.2.3/24 broadcast 2.2.2.255 dev veth4",
		"ip link set br0 up",
		"ip link set veth1 up",
		"ip -n test1 link set veth2 up",
		"ip link set veth3 up",
		"ip -n test2 link set veth4 up",
		"ip -n test1 r add default via 2.2.2.1",
		"ip -n test2 r add default via 2.2.2.1",
		"iptables -I POSTROUTING 1 -t nat -s 2.2.2.0/24 ! -d 2.2.2.0/24 -j MASQUERADE",
		"iptables -I FORWARD -i br0 -j ACCEPT",
		"iptables -I FORWARD -o br0 -j ACCEPT",
		"sysctl -w net.ipv4.ip_forward=1",
	}
	defer func() {
		testutil.RunCommands(t, []string{
			"iptables -D FORWARD -o br0 -j ACCEPT",
			"iptables -D FORWARD -i br0 -j ACCEPT",
			"iptables -D POSTROUTING -t nat -s 2.2.2.0/24 ! -d 2.2.2.0/24 -j MASQUERADE",
			"ip link del veth1",
			"ip link del veth3",
			"ip link del br0",
			"ip netns del test1",
			"ip netns del test2",
		}, true)
	}()
	testutil.RunCommands(t, cmds, false)

	ifs, err := net.Interfaces()
	tr.gwLookup.subnetForHwAddrFunc = func(hwAddr net.HardwareAddr) (network.Subnet, error) {
		for _, i := range ifs {
			if hwAddr.String() == i.HardwareAddr.String() {
				return network.Subnet{Alias: fmt.Sprintf("subnet-%s", i.Name)}, nil
			}
		}

		return network.Subnet{Alias: "subnet"}, nil
	}
	tr.gwLookup.purge()

	test1Ns, err := vnetns.GetFromName("test1")
	require.NoError(t, err)
	defer test1Ns.Close()

	// run tcp server in test1 net namespace
	done := make(chan struct{})
	var server *TCPServer
	err = util.WithNS("/proc", test1Ns, func() error {
		server = NewTCPServerOnAddress("2.2.2.2:0", func(c net.Conn) {})
		return server.Run(done)
	})
	require.NoError(t, err)
	defer close(done)

	var conn *network.ConnectionStats
	t.Run("client in root namespace", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", server.address, 2*time.Second)
		require.NoError(t, err)

		// write some data
		_, err = c.Write([]byte("foo"))
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			var ok bool
			conn, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), getConnections(t, tr))
			return ok && conn.Direction == network.OUTGOING
		}, 2*time.Second, 500*time.Millisecond)

		// conn.Via should be nil, since traffic is local
		require.Nil(t, conn.Via)
	})

	t.Run("client in other namespace", func(t *testing.T) {
		// try connecting to server in test1 namespace
		test2Ns, err := vnetns.GetFromName("test2")
		require.NoError(t, err)
		defer test2Ns.Close()

		var c net.Conn
		err = util.WithNS("/proc", test2Ns, func() error {
			var err error
			c, err = net.DialTimeout("tcp", server.address, 2*time.Second)
			return err
		})
		require.NoError(t, err)
		defer c.Close()

		// write some data
		_, err = c.Write([]byte("foo"))
		require.NoError(t, err)

		var conn *network.ConnectionStats
		require.Eventually(t, func() bool {
			var ok bool
			conn, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), getConnections(t, tr))
			return ok && conn.Direction == network.OUTGOING
		}, 2*time.Second, 500*time.Millisecond)

		// traffic is local, so Via field should not be set
		require.Nil(t, conn.Via)

		// try connecting to something outside
		var dnsClientAddr, dnsServerAddr *net.UDPAddr
		util.WithNS("/proc", test2Ns, func() error {
			dnsClientAddr, dnsServerAddr = doDNSQuery(t, "google.com", "8.8.8.8")
			return nil
		})

		iif := ipRouteGet(t, "", dnsClientAddr.IP.String(), nil)
		ifi := ipRouteGet(t, dnsClientAddr.IP.String(), "8.8.8.8", iif)

		require.Eventually(t, func() bool {
			var ok bool
			conn, ok = findConnection(dnsClientAddr, dnsServerAddr, getConnections(t, tr))
			return ok && conn.Direction == network.OUTGOING
		}, 3*time.Second, 500*time.Millisecond)

		require.NotNil(t, conn.Via)
		require.Equal(t, fmt.Sprintf("subnet-%s", ifi.Name), conn.Via.Subnet.Alias)

	})
}

func TestConnectionAssured(t *testing.T) {
	cfg := testConfig()
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Stop()

	// register test as client
	getConnections(t, tr)

	server := NewUDPServer(func(b []byte, n int) []byte {
		return genPayload(serverMessageSize)
	})

	done := make(chan struct{})
	server.Run(done, clientMessageSize)
	defer close(done)

	c, err := net.DialTimeout("udp", server.address, time.Second)
	require.NoError(t, err)
	defer c.Close()

	// do two exchanges to make the connection "assured"
	for i := 0; i < 2; i++ {
		_, err = c.Write(genPayload(clientMessageSize))
		require.NoError(t, err)

		buf := make([]byte, serverMessageSize)
		_, err = c.Read(buf)
		require.NoError(t, err)
	}

	var conn *network.ConnectionStats
	require.Eventually(t, func() bool {
		conns := getConnections(t, tr)
		var ok bool
		conn, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), conns)
		return ok && conn.MonotonicSentBytes > 0 && conn.MonotonicRecvBytes > 0
	}, 3*time.Second, 500*time.Millisecond, "could not find udp connection")

	// verify the connection is marked as assured
	connMp, err := tr.getMap(probes.ConnMap)
	require.NoError(t, err)
	defer connMp.Close()
	key, err := connTupleFromConn(c, conn.Pid, conn.NetNS)
	stats := &ConnStatsWithTimestamp{}
	err = connMp.Lookup(unsafe.Pointer(key), unsafe.Pointer(stats))
	require.NoError(t, err)
	require.True(t, stats.isAssured())
}

func TestConnectionNotAssured(t *testing.T) {
	cfg := testConfig()
	cfg.BPFDebug = true
	tr, err := NewTracer(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Stop()

	// register test as client
	getConnections(t, tr)

	server := NewUDPServer(func(b []byte, n int) []byte {
		return nil
	})

	done := make(chan struct{})
	server.Run(done, clientMessageSize)
	defer close(done)

	c, err := net.DialTimeout("udp", server.address, time.Second)
	require.NoError(t, err)
	defer c.Close()

	_, err = c.Write(genPayload(clientMessageSize))
	require.NoError(t, err)

	var conn *network.ConnectionStats
	require.Eventually(t, func() bool {
		conns := getConnections(t, tr)
		var ok bool
		conn, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), conns)
		return ok && conn.MonotonicSentBytes > 0 && conn.MonotonicRecvBytes == 0
	}, 3*time.Second, 500*time.Millisecond, "could not find udp connection")

	// verify the connection is marked as not assured
	connMp, err := tr.getMap(probes.ConnMap)
	require.NoError(t, err)
	defer connMp.Close()
	key, err := connTupleFromConn(c, conn.Pid, conn.NetNS)
	stats := &ConnStatsWithTimestamp{}
	err = connMp.Lookup(unsafe.Pointer(key), unsafe.Pointer(stats))
	require.NoError(t, err)
	require.False(t, stats.isAssured())
}

func TestNewConntracker(t *testing.T) {
	ctrl := gomock.NewController(t)

	cfg := testConfig()

	mockCreator := func(_ *config.Config) (netlink.Conntracker, error) {
		return netlink.NewMockConntracker(ctrl), nil
	}

	errCreator := func(_ *config.Config) (netlink.Conntracker, error) {
		return nil, assert.AnError
	}

	mockConntracker := netlink.NewMockConntracker(ctrl)
	noopConntracker := netlink.NewNoOpConntracker()

	tests := []struct {
		conntrackEnabled  bool
		ignoreInitFailure bool
		creator           func(*config.Config) (netlink.Conntracker, error)

		conntracker netlink.Conntracker
		err         error
	}{
		{false, false, mockCreator, noopConntracker, nil},
		{true, true, mockCreator, mockConntracker, nil},
		{true, true, errCreator, noopConntracker, nil},
		{true, false, mockCreator, mockConntracker, nil},
		{true, false, errCreator, nil, assert.AnError},
	}

	for _, te := range tests {
		cfg.EnableConntrack = te.conntrackEnabled
		cfg.IgnoreConntrackInitFailure = te.ignoreInitFailure
		c, err := newConntracker(cfg, te.creator)
		if te.conntracker != nil {
			require.IsType(t, te.conntracker, c)
		} else {
			require.Nil(t, c)
		}

		if te.err != nil {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestUDPConnExpiryTimeout(t *testing.T) {
	streamTimeout, err := sysctl.NewInt("/proc", "net/netfilter/nf_conntrack_udp_timeout_stream", 0).Get()
	require.NoError(t, err)
	timeout, err := sysctl.NewInt("/proc", "net/netfilter/nf_conntrack_udp_timeout", 0).Get()
	require.NoError(t, err)

	tr, err := NewTracer(testConfig())
	require.NoError(t, err)
	defer tr.Stop()

	require.Equal(t, uint64(time.Duration(timeout)*time.Second), tr.udpConnTimeout(false))
	require.Equal(t, uint64(time.Duration(streamTimeout)*time.Second), tr.udpConnTimeout(true))
}
