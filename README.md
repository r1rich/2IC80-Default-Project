# ARP Poisoning Tool

This is a Python-based command-line tool for conducting ARP poisoning attacks and optionally forwarding intercepted packets in a Man-in-the-Middle (MITM) configuration.

(`main.py`) Creates ARP poisoning threads that intercept traffic between a victim and a target machine through an Ether port.

It uses Scapy to craft and send ARP packets in either **reply** or **request** mode, poisoning the ARP cache of the victim.

## Usage

# Basic syntax:
```bash
sudo python3 main.py <ipAttacker> <macAttacker> <ipVictim> <macVictim> <ipToSpoof> <macTarget> <iface> [OPTIONS]
```
Positional Arguments:
  <ipAttacker>      Attacker's IP address (your local machine) \
  <macAttacker>     Attacker's MAC address \
  <ipVictim>        Victim's IP address \
  <macVictim>       Victim's MAC address \
  <ipToSpoof>       IP address you want to spoof (e.g., the gateway) \
  <macTarget>       MAC address of the spoofed device (e.g., gateway MAC) \
  <iface>           Network interface to use (e.g., eth0, wlan0) \ 

Optional Flags: \
  --mode reply|request      Type of ARP packet to send (default: reply)  

  --bi-directional          Enable two-way spoofing (spoof victim and gateway)  

  --mitm                    Enable packet forwarding (MITM)     

  --verbose                 Enable detailed output (debug/info)    
