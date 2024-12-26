import threading
from scapy.all import sniff
from firewall import packet_callback, monitor_suspicious_activity

# A global variable to control the sniffing process
monitoring_active = False
sniffer_thread = None  # Reference to the sniffing thread

def start_monitoring(log_text):
    """Start sniffing packets in a separate thread."""
    global monitoring_active, sniffer_thread
    monitoring_active = True

    def monitor():
        """Run the packet sniffer."""
        sniff(
            prn=lambda packet: packet_callback(packet, log_text),
            store=0,
            stop_filter=lambda x: not monitoring_active  # Stop sniffing based on the flag
        )
        print("Sniffing stopped.")

    # Start sniffing in a new thread
    sniffer_thread = threading.Thread(target=monitor, daemon=True)
    sniffer_thread.start()

    # Start monitoring suspicious activity in a separate thread
    threading.Thread(target=monitor_suspicious_activity, daemon=True).start()

def stop_monitoring():
    """Stop the packet monitoring process."""
    global monitoring_active
    monitoring_active = False
    print("Monitoring will stop shortly.")
