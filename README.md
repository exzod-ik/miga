# Make Internet Great Again - M.I.G.A.

This is another alternative set of utilities for bypassing DPI and IP blocking. You'll need a Linux VPS (tested on Debian 12) for the server side. The client side is implemented for Windows and uses Windivert. It redirects outgoing packets according to whitelist rules (specified IP addresses, domain names or applications).

Basic operating principle:
- the client intercepts packets and analyzes them according to established rules;
- if the packet matches the redirection criteria, the client encrypts it, packs it into a UDP datagram, and sends it to the server on a random port from a specified range.

## Client TCP MSS

Set the optional global `"tunnel_max_mss"` field in the client `config.json`,
alongside `"log_level"` and `"servers"`:

```json
"tunnel_max_mss": 1400
```

The default is 1400 when the field is absent. The value must be an integer
from 1 to 65535. It caps the TCP MSS option in tunneled SYN and SYN-ACK
packets in both directions; a smaller advertised MSS is left unchanged.
Reload the client configuration or restart the client to apply a change.
MIGA Agent preserves this field when saving the configuration.
