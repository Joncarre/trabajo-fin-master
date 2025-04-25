# This script is used to test the PacketProcessor class from the src.data_processing.packet_processor module.
# It processes a PCAP file and prints out basic statistics about the packets, including layer 4 protocol distribution.

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_processing.packet_processor import PacketProcessor

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_processor.py <path_to_pcap_file>")
        return
    
    pcap_file = sys.argv[1]
    processor = PacketProcessor()
    
    # Process the PCAP file
    print(f"Processing PCAP file: {pcap_file}")
    processed_packets = processor.process_pcap_file(pcap_file)
    
    # Show basic statistics
    if processed_packets:
        print(f"\nProcessed {len(processed_packets)} packets")
        
        # Count layer 4 protocols
        l4_protocols = {}
        for packet in processed_packets:
            proto = packet['layer4'].get('protocol', 'unknown')
            l4_protocols[proto] = l4_protocols.get(proto, 0) + 1
        
        print("\nLayer 4 Protocol Distribution:")
        for proto, count in l4_protocols.items():
            print(f"  {proto.upper()}: {count} packets ({count/len(processed_packets)*100:.1f}%)")
        
        # Show a sample packet
        print("\nSample packet data (first packet):")
        sample = processed_packets[0]
        print(f"  Timestamp: {sample.get('timestamp')}")
        print(f"  Source IP: {sample['layer3'].get('src_ip')}")
        print(f"  Destination IP: {sample['layer3'].get('dst_ip')}")
        if 'version' in sample['layer3']:
            print(f"  IP Version: {sample['layer3']['version']}")
        
        # Show layer 4 info based on protocol
        l4 = sample['layer4']
        proto = l4.get('protocol')
        if proto == 'tcp' or proto == 'udp':
            print(f"  Source Port: {l4.get('src_port')}")
            print(f"  Destination Port: {l4.get('dst_port')}")
            if proto == 'tcp' and 'flags' in l4:
                print(f"  TCP Flags: {l4['flags']}")
        elif proto == 'icmp' and 'type' in l4:
            print(f"  ICMP Type: {l4['type']} ({l4.get('type_name', 'unknown')})")
    else:
        print("No packets were processed.")

if __name__ == "__main__":
    main()