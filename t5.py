from scapy.all import sniff

def packet_callback(packet):
    # Display relevant information about the packet
    print(f"Source IP: {packet[1].src}")
    print(f"Destination IP: {packet[1].dst}")
    print(f"Protocol: {packet[1].proto}")
    print(f"Payload: {bytes(packet[1].payload)}")
    print("-" * 50)

def main():
    print("Starting packet sniffer...")
    # Start sniffing packets
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    main()