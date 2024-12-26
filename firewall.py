from collections import Counter
import time
import threading
import tkinter as tk

# Global counters for packet statistics
protocol_counter = Counter()
ip_counter = Counter()
connection_tracker = {}  # Track TCP connections
traffic_volume = {'sent': 0, 'received': 0}  # Track bytes sent and received

# Simple firewall rules
allowed_ips = ["192.168.1.1"]  # Allow only this IP
blocked_ports = [80, 443]      # Block HTTP and HTTPS

# Track suspicious activity
suspicious_alerts = []

def check_packet_rules(packet):
    """Check a packet against predefined rules and return 'Allowed' or 'Blocked'."""
    try:
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst

            # Block specific IP rule
            if ip_src == "192.168.1.1":
                return "Blocked"
            
            # Check if the packet is UDP and block it
            if packet.haslayer("TCP"):
                return "Blocked"

    except Exception as e:
        return f"Error: {e}"

def packet_callback(packet, log_text):
    """Process each captured packet."""
    global traffic_volume

    try:
        # Check packet rules
        action = check_packet_rules(packet)
        log_msg = f"Packet: {packet.summary()} - {action}"

        # Update log (GUI)
        if log_text:
            log_text.insert(tk.END, log_msg + "\n")
            log_text.see(tk.END)

        # Determine protocol and update counters
        if packet.haslayer("TCP"):
            protocol = "TCP"
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                ip_counter[ip_src] += 1
                ip_counter[ip_dst] += 1

                # Track TCP connections (Source IP, Destination IP, Source Port, Destination Port)
                connection_key = (ip_src, ip_dst, packet["TCP"].sport, packet["TCP"].dport)
                if connection_key not in connection_tracker:
                    connection_tracker[connection_key] = time.time()

        elif packet.haslayer("UDP"):
            protocol = "UDP"
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        protocol_counter[protocol] += 1

        # Traffic volume tracking
        if packet.haslayer("IP"):
            traffic_volume['sent'] += len(packet)
        
    except Exception as e:
        print(f"Error processing packet: {e}")

def monitor_suspicious_activity():
    """Monitor for suspicious activities like DoS and frequent communication."""
    global suspicious_alerts, connection_tracker, ip_counter, traffic_volume

    # Check for high traffic volume (Potential DoS Attack)
    if traffic_volume['sent'] > 1000000:  # Threshold for total traffic (1MB)
        suspicious_alerts.append("Suspicious: High traffic volume detected!")

    # Check for high packet rates (frequent communication with unknown IPs)
    threshold = 100  # Packet rate threshold
    for ip, count in ip_counter.items():
        if count > threshold:
            suspicious_alerts.append(f"Suspicious: Frequent communication with IP {ip} detected!")

    # Check for long TCP connections (Duration > 10 seconds)
    current_time = time.time()
    for connection_key, start_time in connection_tracker.items():
        duration = current_time - start_time
        if duration > 10:  # Long duration connection alert (10 seconds)
            suspicious_alerts.append(f"Suspicious: Long TCP connection detected between {connection_key[0]} and {connection_key[1]}")

    if suspicious_alerts:
        print("\nSuspicious Activity Detected!")
        for alert in suspicious_alerts:
            print(alert)
