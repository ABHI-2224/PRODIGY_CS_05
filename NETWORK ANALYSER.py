from scapy.all import *

def packet_callback(packet):
    # Display basic information about the packet
    print(f"Packet: {packet.summary()}")
    
    # Extract and display the source and destination IP addresses
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
    
    # Extract and display protocol information
    if TCP in packet:
        print(f"Protocol: TCP")
    elif UDP in packet:
        print(f"Protocol: UDP")
    else:
        print(f"Protocol: {packet.proto}")
    
    # Display payload data if available
    if Raw in packet:
        payload = packet[Raw].load
        print(f"Payload: {payload}")

    print("-" * 50)

def main():
    print("Starting packet sniffer...")
    # Start sniffing packets and apply the packet_callback function to each packet
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
