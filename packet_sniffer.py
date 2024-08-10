from scapy.all import sniff, IP
from scapy.layers import inet
from datetime import datetime

current_time = str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ".txt"

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Identify the protocol layer
        if packet.haslayer("TCP"):
            proto_name = "TCP"
        elif packet.haslayer("UDP"):
            proto_name = "UDP"
        else:
            proto_name = packet[IP].proto 
        
        # Get payload data
        payload = bytes(packet[IP].payload)
        
        # Try decoding with various encodings
        try:
            payload_str = payload.decode('utf-8')
        except UnicodeDecodeError:
            try:
                payload_str = payload.decode('latin1')
            except UnicodeDecodeError:
                payload_str = payload.hex()

        protocol = f"Protocol: {proto_name}"
        source_ip = f"Source IP: {ip_src}"
        dest_ip = f"Destination IP: {ip_dst}"
        payload = f"Payload (characters or hex): {payload_str}"
        
        print(protocol)
        print(source_ip)
        print(dest_ip)
        print(payload)
        print("-" * 50)
        
        #saves packet into a text file, naming is based on the time the code was executed
        with open(current_time, "a", encoding='utf-8') as logs:
            logs.write("Time: " + str(datetime.now()) + "\n")
            logs.write(protocol + "\n")
            logs.write(source_ip + "\n")
            logs.write(dest_ip + "\n")
            logs.write(payload + "\n")
            
            logs.write("-" * 50 + "\n\n")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
