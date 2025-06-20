# ARP Poisoning Tool

This script (`main.py`) performs ARP poisoning to intercept and redirect traffic between a victim and a target machine on a local network.

It uses Scapy to craft and send ARP packets in either **reply** or **request** mode, enabling a man-in-the-middle (MITM) setup.

## Usage

```bash
sudo python3 main.py <ipAttacker> <macAttacker> <ipVictim> <macVictim> <ipToSpoof> <iface> [--mode reply|request]
