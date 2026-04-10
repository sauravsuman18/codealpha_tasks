from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def packet_callback(packet):
    # Skip non-IP packets
    if not packet.haslayer(IP):
        return

    print("\n=== Packet Captured ===")

    ip_layer = packet[IP]
    print(f"Source IP: {ip_layer.src}")
    print(f"Destination IP: {ip_layer.dst}")

    # Protocol detection
    if ip_layer.proto == 6:
        print("Protocol: TCP")
    elif ip_layer.proto == 17:
        print("Protocol: UDP")
    elif ip_layer.proto == 1:
        print("Protocol: ICMP")
    else:
        print(f"Protocol: Other ({ip_layer.proto})")

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"TCP Ports: {tcp.sport} -> {tcp.dport}")

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"UDP Ports: {udp.sport} -> {udp.dport}")

    # Payload
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"Payload (first 50 bytes): {payload[:50]}")


def main():
    print("Starting network sniffer...")
    sniff(prn=packet_callback, store=0, timeout=10)


if __name__ == "__main__":
    main()