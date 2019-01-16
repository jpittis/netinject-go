Warning: This is not production ready code, just a quick prototype.

# Netinject

Netinject is a daemon which lets you create network failures for chosen TCP ports. In
essence, you tell it to create or delete iptables rules using a protobuf over HTTP API. It
takes care of cleaning up the iptables rules on exit.
