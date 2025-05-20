from scapy.all import rdpcap, IP
from collections import Counter

pcap_file = "pcaps/simulated_attack_1.pcap"
packets = rdpcap(pcap_file)

src_ips = []
dst_ips = []

for pkt in packets:
    if IP in pkt:
        src_ips.append(pkt[IP].src)
        dst_ips.append(pkt[IP].dst)

# Count frequency
src_counts = Counter(src_ips)
dst_counts = Counter(dst_ips)

print("Top 10 Source IPs:")
for ip, count in src_counts.most_common(10):
    print(f"{ip}: {count} packets")

print("\nTop 10 Destination IPs:")
for ip, count in dst_counts.most_common(10):
    print(f"{ip}: {count} packets")
