from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw
from datetime import datetime
import csv
import os

CSV_FILE = "packet_logs.csv"
ALERT_FILE = "alerts.log"

SUSPICIOUS_PORTS = [21, 23, 445, 3389]

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0
http_count = 0
https_count = 0

# Create CSV file
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Timestamp",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Source_Port",
            "Destination_Port",
            "Payload"
        ])


def generate_alert(message):
    print(f"\n[ALERT] {message}")

    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        file.write(message + "\n")


def get_protocol(packet):

    global tcp_count
    global udp_count
    global icmp_count
    global dns_count
    global http_count
    global https_count

    if packet.haslayer(DNS):
        dns_count += 1
        return "DNS"

    if packet.haslayer(ICMP):
        icmp_count += 1
        return "ICMP"

    if packet.haslayer(TCP):

     tcp_count += 1

     sport = packet[TCP].sport
     dport = packet[TCP].dport

    if sport == 80 or dport == 80:
        http_count += 1
        return "HTTP"

    if sport == 443 or dport == 443:
        https_count += 1
        return "HTTPS"

    return "TCP"

    if packet.haslayer(UDP):
        udp_count += 1
        return "UDP"

    return "OTHER"


def extract_payload(packet, protocol):

    if not packet.haslayer(Raw):
        return ""

    # HTTPS traffic is encrypted
    if protocol == "HTTPS":
        return "[ENCRYPTED TLS DATA]"

    try:
        payload = packet[Raw].load.decode(
            "utf-8",
            errors="ignore"
        )

        payload = ''.join(
            c for c in payload if c.isprintable()
        )

        return payload[:100]

    except:
        return "[BINARY DATA]"


def process_packet(packet):

    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    src_port = "-"
    dst_port = "-"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    payload = extract_payload(
        packet,
        protocol
    )

    print("\n" + "=" * 50)
    print(f"Packet #  : {packet_count}")
    print(f"Time      : {timestamp}")
    print(f"Source IP : {src_ip}")
    print(f"Dest IP   : {dst_ip}")
    print(f"Protocol  : {protocol}")
    print(f"Src Port  : {src_port}")
    print(f"Dst Port  : {dst_port}")

    if payload:
        print(f"Payload   : {payload}")

    with open(
        CSV_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            payload
        ])

    if (
        dst_port != "-"
        and isinstance(dst_port, int)
        and dst_port in SUSPICIOUS_PORTS
    ):
        generate_alert(
            f"{timestamp} Suspicious Port Access: "
            f"{src_ip} -> {dst_ip}:{dst_port}"
        )


def print_summary():

    print("\n")
    print("=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)

    print(f"Total Packets : {packet_count}")
    print(f"TCP Packets   : {tcp_count}")
    print(f"UDP Packets   : {udp_count}")
    print(f"ICMP Packets  : {icmp_count}")
    print(f"DNS Packets   : {dns_count}")
    print(f"HTTP Packets  : {http_count}")
    print(f"HTTPS Packets : {https_count}")

    print("=" * 60)
    print(f"CSV Log    : {CSV_FILE}")
    print(f"Alerts Log : {ALERT_FILE}")
    print("=" * 60)


print("=" * 60)
print("ADVANCED NETWORK SNIFFER")
print("Capturing 100 packets...")
print("=" * 60)

try:

    sniff(
        prn=process_packet,
        store=False,
        count=100
    )

    print_summary()

except KeyboardInterrupt:

    print("\nCapture stopped by user.")
    print_summary()