import tkinter as tk
from tkinter import ttk, filedialog
from sniffer import start_monitoring, stop_monitoring
from firewall import protocol_counter, ip_counter, suspicious_alerts
from visualizer import plot_protocol_distribution, plot_ip_distribution, analyze_packets
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading

def export_logs(log_text):
    """Export logs to a file."""
    logs = log_text.get("1.0", tk.END)
    if not logs.strip():
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(logs)

def create_gui():
    """Create and manage the GUI."""
    root = tk.Tk()
    root.title("Firewall with Packet Visualization")
    root.geometry("800x700")
    root.resizable(True, True)

    # Apply a theme
    style = ttk.Style(root)
    style.theme_use("clam")  # Change to "default", "alt", etc., for other themes.

    # Header
    header_label = ttk.Label(root, text="Firewall & Packet Visualization", font=("Arial", 16, "bold"))
    header_label.pack(pady=10)

    # Control Frame
    control_frame = ttk.Frame(root)
    control_frame.pack(pady=10, padx=20, fill=tk.X)

    # Progress Bar
    progress = ttk.Progressbar(control_frame, orient="horizontal", mode="indeterminate", length=200)
    progress.grid(row=0, column=0, columnspan=3, pady=5)

    # Buttons
    start_monitoring_button = ttk.Button(control_frame, text="Start Monitoring",
                                         command=lambda: [progress.start(), threading.Thread(target=start_monitoring, args=(log_text,)).start()])
    start_monitoring_button.grid(row=1, column=0, padx=10, pady=5)

    stop_monitoring_button = ttk.Button(control_frame, text="Stop Monitoring",
                                        command=lambda: [progress.stop(), stop_monitoring()])
    stop_monitoring_button.grid(row=1, column=1, padx=10, pady=5)

    analyze_button = ttk.Button(control_frame, text="Analyze Packets", command=analyze_packets)
    analyze_button.grid(row=1, column=2, padx=10, pady=5)

    protocol_button = ttk.Button(control_frame, text="Show Protocol Distribution", command=plot_protocol_distribution)
    protocol_button.grid(row=2, column=0, padx=10, pady=5)

    ip_button = ttk.Button(control_frame, text="Show IP Distribution", command=plot_ip_distribution)
    ip_button.grid(row=2, column=1, padx=10, pady=5)

    export_button = ttk.Button(control_frame, text="Export Logs", command=lambda: export_logs(log_text))
    export_button.grid(row=2, column=2, padx=10, pady=5)

    # Status Label
    status_label = ttk.Label(root, text="Status: Monitoring Stopped", font=("Arial", 12), foreground="red")
    status_label.pack(pady=5)

    # Log Frame
    log_frame = ttk.LabelFrame(root, text="Logs", padding=10)
    log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Courier New", 10))
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(log_frame, command=log_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    log_text.config(yscrollcommand=scrollbar.set)

    # Suspicious Alerts
    alert_button = ttk.Button(control_frame, text="Show Suspicious Activity", command=lambda: show_alerts())
    alert_button.grid(row=3, column=0, padx=10, pady=5)

    def show_alerts():
        """Display suspicious activity alerts."""
        for alert in suspicious_alerts:
            log_text.insert(tk.END, alert + "\n")
            log_text.see(tk.END)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
