import matplotlib.pyplot as plt
from firewall import protocol_counter, ip_counter

def plot_protocol_distribution():
    """Generate a pie chart of protocol distribution."""
    if not protocol_counter or sum(protocol_counter.values()) == 0:
        print("No data to display for protocol distribution!")
        return

    # Print the counter for debugging
    print(f"Protocol Counter: {protocol_counter}")

    # Extract data for plotting
    labels, counts = zip(*protocol_counter.items())
    total = sum(counts)

    # Normalize counts to show meaningful percentages
    counts = [count for count in counts if count > 0]
    labels = [label for i, label in enumerate(labels) if protocol_counter[label] > 0]

    plt.figure(figsize=(6, 6))
    plt.pie(counts, labels=labels, autopct=lambda p: f'{p:.1f}%\n({int(p * total / 100)})', startangle=90)
    plt.title("Protocol Distribution")
    plt.show()

def plot_ip_distribution():
    """Generate a bar chart for top IP addresses."""
    if not ip_counter:
        print("No data to display for IP distribution!")
        return

    top_ips = ip_counter.most_common(10)
    ips, counts = zip(*top_ips)
    plt.figure(figsize=(8, 6))
    plt.bar(ips, counts, color="skyblue")
    plt.xticks(rotation=45)
    plt.title("Top 10 IP Addresses")
    plt.ylabel("Packet Count")
    plt.xlabel("IP Address")
    plt.tight_layout()
    plt.show()

def analyze_packets():
    """Analyze captured packets and provide insights."""
    # Display total number of captured packets
    total_packets = sum(protocol_counter.values())
    print(f"Total Packets Captured: {total_packets}")
    
    # Display top 5 most common protocols
    if protocol_counter:
        print("\nTop 5 Protocols:")
        for protocol, count in protocol_counter.most_common(5):
            print(f"{protocol}: {count} packets")

    # Display top 5 most frequent IP addresses
    if ip_counter:
        print("\nTop 5 IP Addresses:")
        for ip, count in ip_counter.most_common(5):
            print(f"{ip}: {count} packets")

    # Display any IP addresses that have captured unusually high number of packets
    threshold = total_packets * 0.1  # Consider IPs with more than 10% of total packets
    print("\nUnusual IP Addresses (more than 10% of total packets):")
    for ip, count in ip_counter.items():
        if count > threshold:
            print(f"{ip}: {count} packets")

    # Additional analysis can be added here, such as identifying unknown protocols or abnormal traffic patterns.

