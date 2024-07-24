from scapy.all import get_if_list

# Print all available network interfaces
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")
