# Make Internet Great Again - M.I.G.A.

This is another alternative set of utilities for bypassing DPI and IP blocking. You'll need a Linux VPS (tested on Debian 12) for the server side. The client side is implemented for Windows and uses Windivert. It redirects outgoing packets according to whitelist rules (specified IP addresses or applications).

Basic operating principle:
- the client intercepts packets and analyzes them according to established rules;
- if the packet matches the redirection criteria, the client encrypts it, packs it into a UDP datagram, and sends it to the server on a random port from a specified range.
