import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from scapy.arch.windows import get_windows_if_list
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

packets = []
sniffing_event = threading.Event()

def packet_callback(packet):
    global packets
    try:
        packet_info = {
            "Timestamp": pd.to_datetime(packet.time, unit='s').strftime('%Y-%m-%d %H:%M:%S'),
            "Source IP": packet[IP].src if packet.haslayer(IP) else None,
            "Destination IP": packet[IP].dst if packet.haslayer(IP) else None,
            "Protocol": packet[IP].proto if packet.haslayer(IP) else None,
            "Source Port": packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else None),
            "Destination Port": packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else None),
            "Payload Length": len(packet) if packet.haslayer(IP) else None
        }
        packets.append(packet_info)
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: not sniffing_event.is_set())

def save_to_csv(filename):
    global packets
    if not packets:
        messagebox.showwarning("No Data", "No packets captured to save.")
        return
    df = pd.DataFrame(packets)
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

def plot_protocol_distribution(filename):
    df = pd.read_csv(filename)
    protocol_counts = df['Protocol'].value_counts()

    plt.figure(figsize=(10, 6))
    protocol_counts.plot(kind='bar')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Protocol Distribution')
    plt.show()

def plot_payload_length_distribution(filename):
    df = pd.read_csv(filename)

    plt.figure(figsize=(10, 6))
    df['Payload Length'].dropna().plot(kind='hist', bins=50)
    plt.xlabel('Payload Length')
    plt.ylabel('Frequency')
    plt.title('Payload Length Distribution')
    plt.show()

def detect_anomalies(filename, threshold=100):
    df = pd.read_csv(filename)
    src_counts = df['Source IP'].value_counts()

    potential_threats = src_counts[src_counts > threshold]
    if not potential_threats.empty:
        print("Potential threats detected:")
        print(potential_threats)
    else:
        print("No anomalies detected.")

def stop_sniffing():
    sniffing_event.clear()
    print("Stopping packet capture...")

def show_statistics():
    print(f"Total packets captured: {len(packets)}")

def select_file():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    return filename

def start_gui():
    def on_start():
        global filename  # Make filename global so it can be accessed in on_stop()
        interface = interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        filename = select_file()  # Assign filename globally
        if not filename:
            return

        sniffing_event.set()
        global sniff_thread
        sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
        sniff_thread.start()

        stop_button.configure(state="normal")
        start_button.configure(state="disabled")

    def on_stop():
        stop_sniffing()
        stop_button.configure(state="disabled")
        start_button.configure(state="normal")

        sniff_thread.join()

        save_to_csv(filename)
        plot_protocol_distribution(filename)
        plot_payload_length_distribution(filename)
        detect_anomalies(filename)
        messagebox.showinfo("Done", "Analysis complete!")

    root = ctk.CTk()
    root.title("Packet Sniffer")
    root.geometry("600x400")

    ctk.CTkLabel(root, text="Select Correct Network Interface:", font=("Arial", 12)).pack(pady=10)

    interface_var = ctk.StringVar(root)
    interface_var.set("Select Interface")
    interfaces = get_windows_if_list()
    interface_menu = ctk.CTkOptionMenu(root, variable=interface_var, values=[iface['name'] for iface in interfaces])
    interface_menu.configure(font=("Arial", 12))
    interface_menu.pack(pady=10)

    start_button = ctk.CTkButton(root, text="Start Sniffing", command=on_start, font=("Arial", 12))
    start_button.pack(pady=10)

    stop_button = ctk.CTkButton(root, text="Stop Sniffing", command=on_stop, font=("Arial", 12), state="disabled")
    stop_button.pack(pady=10)

    ctk.CTkButton(root, text="Exit", command=root.quit, font=("Arial", 12)).pack(pady=10)

    root.mainloop()

def main():
    start_gui()

if __name__ == "__main__":
    main()