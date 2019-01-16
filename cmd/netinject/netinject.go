package main

import (
	"io/ioutil"
	"log"
	"net/http"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gogo/protobuf/proto"
	"github.com/jpittis/netinject/pkg/api"
	"github.com/jpittis/netinject/pkg/netinject"
	"github.com/jpittis/netinject/pkg/session"
)

const (
	// FilterTable is the default iptables table for filtering packets.
	FilterTable = "filter"
	// InputChain is the default chain for inbound packets on the filter table.
	InputChain = "INPUT"
	// OutputChain is the default chain for outbound packets on the filter table.
	OutputChain = "OUTPUT"

	// DefaultProtocol will be used when creating iptables rules. It can be overridden
	// with a command line argument.
	DefaultProtocol = iptables.ProtocolIPv4

	// ListenAddr is the address that our server listens on for updates to add or remove
	// network failures.
	ListenAddr = "0.0.0.0:5555"
)

func main() {
	netinject := netinject.NetInject{
		Session: session.Session{
			Protocol:    DefaultProtocol,
			Table:       FilterTable,
			InputChain:  InputChain,
			OutputChain: OutputChain,
		},
	}

	log.Printf("Running netinject using the '%s' table...", netinject.Session.Table)

	err := netinject.Session.Validate()
	if err != nil {
		// We can exit immediately because there's nothing to cleanup.
		log.Fatal(err)
	}

	defer func() {
		err := netinject.Session.Cleanup()
		if err != nil {
			log.Println(err)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("HTTP handler error %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var update *api.Update
		err = proto.Unmarshal(data, update)
		if err != nil {
			log.Printf("HTTP handler error %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = netinject.Update(update)
		if err != nil {
			log.Printf("HTTP handler error %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	err = http.ListenAndServe(ListenAddr, nil)
	if err != nil {
		// Print error but do not exit because we want to run the session cleanup.
		log.Println(err)
	}
}
