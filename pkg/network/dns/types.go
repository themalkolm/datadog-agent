package dns

import (
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

// ReverseDNS translates IPs to names
type ReverseDNS interface {
	Resolve([]util.Address) map[util.Address][]string
	GetDNSStats() map[Key]map[string]Stats
	GetStats() map[string]int64
	Close()
}

// Key is an identifier for a set of DNS connections
type Key struct {
	ServerIP   util.Address
	ClientIP   util.Address
	ClientPort uint16
	// ConnectionType will be either TCP or UDP
	Protocol uint8
}

// Stats holds statistics corresponding to a particular domain
type Stats struct {
	Timeouts          uint32
	SuccessLatencySum uint64
	FailureLatencySum uint64
	CountByRcode      map[uint32]uint32
}
