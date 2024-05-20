from scapy.all import sniff,conf,Raw
conf.L3socket=Raw

# Define the packet processing function
def process_packet(packet):
    # Print out the summary of the packet
    print(packet.summary())

# Start sniffing the network
sniff(prn=process_packet, store=False)
