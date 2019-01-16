package netinject

import (
	"fmt"
	"sync"

	"github.com/jpittis/netinject/pkg/api"
	"github.com/jpittis/netinject/pkg/session"
)

// NetInject is used to inject network failures at layer 3 for all TCP traffic on a given
// port using iptables. It is safe for concurrent access. On program exit,
// netinject.Session.Cleanup() should be called.
type NetInject struct {
	sync.Mutex
	Session session.Session
}

// Update creates or deletes a TCP network failure on the given port and direction.
func (n *NetInject) Update(update *api.Update) error {
	n.Lock()
	defer n.Unlock()

	portStr := fmt.Sprint(update.Port)
	rule := dropAllTCPPacketsForPortRule(portStr)

	if update.Drop {
		switch update.Direction {
		case api.Direction_INBOUND:
			return n.Session.CreateInputRule(portStr, rule)
		case api.Direction_OUTBOUND:
			return n.Session.CreateOutputRule(portStr, rule)
		default:
			panic(fmt.Sprintf("unknown direction %s", update.Direction))
		}

	} else {
		switch update.Direction {
		case api.Direction_INBOUND:
			return n.Session.DeleteInputRule(portStr)
		case api.Direction_OUTBOUND:
			return n.Session.DeleteOutputRule(portStr)
		default:
			panic(fmt.Sprintf("unknown direction %s", update.Direction))
		}
	}
}

func dropAllTCPPacketsForPortRule(portStr string) session.Rule {
	return []string{
		"-p", "tcp", "--dport", portStr, "-j", "DROP",
	}
}
