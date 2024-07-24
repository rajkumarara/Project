import sys
from scapy.all import *

# Global verbose flag
verbose = False

# Function to handle each packet
def handle_packet(packet, log):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
        if verbose:
            print(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Function to sanitize interface name for log file
def sanitize_filename(name):
    return "".join(c if c.isalnum() else "_" for c in name)

# Main function to start packet sniffing
def main(interface, verbose_flag=False):
    global verbose
    verbose = verbose_flag
    sanitized_interface = sanitize_filename(interface)
    logfile_name = f"sniffer_{sanitized_interface}_log.txt"
    with open(logfile_name, 'w') as logfile:
        try:
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

# Check if the script is being run directly
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    verbose_flag = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose_flag = True
    main(sys.argv[1], verbose_flag)
