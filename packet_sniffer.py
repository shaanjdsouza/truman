import socket
import subprocess
import threading
import time
import argparse
import platform
from collections import defaultdict

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from scapy.all import IP, ICMP, sniff

# counters
counters = defaultdict(int)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))
my_ip = s.getsockname()[0]
s.close()
DURATION = 10

# packet
def process_packet(packet):
    if IP in packet and ICMP in packet:
        if packet[IP].src == my_ip and packet[IP].dst == counters["target_ip"]:
            counters["sent"] += 1
        elif packet[IP].src == counters["target_ip"] and packet[IP].dst == my_ip:
            counters["received"] += 1

def run_ping(target: str):
    if platform.system() == "Windows":
        command = ["ping", "-n", str(DURATION), target]
    else:
        command = ["ping", "-c", str(DURATION * 2), "-i", "0.5", target]

    subprocess.run(
        command,
        stdout = subprocess.DEVNULL,
        stderr = subprocess.DEVNULL
    )

# table
def build_table(elapsed: float,target: str) -> Table:
    sent     = counters["sent"]
    received = counters["received"]
    loss     = max(0, sent - received)
    loss_pct = (loss / max(1, sent)) * 100
    remaining = max(0, DURATION - int(elapsed))

    table = Table(title=f"Ping Tracker  —  {remaining}s remaining", border_style="cyan")
    table.add_column("Metric",    style="bold white",  justify="left")
    table.add_column("Value",     style="bold yellow",  justify="right")
    
    table.add_row("Target",          target)
    table.add_row("My IP",           my_ip)
    table.add_row("Elapsed (s)",     f"{elapsed:.1f}")
    table.add_row("Packets Sent",    str(sent))
    table.add_row("Packets Received",str(received))
    table.add_row("Packet Loss",     f"{loss_pct:.1f}%")

    return table

def main(argv=None):
    console = Console()
    console.print(Panel(f"[bold cyan]Monitoring network traffic for {DURATION} seconds...[/bold cyan]\n"
                        f"[dim]Detected IP: {my_ip}[/dim]"))
    
    parser = argparse.ArgumentParser(prog="truman trace", description="Trace ICMP packets to a target")
    parser.add_argument("-t","--target",required=True)
    args = parser.parse_args(argv)

    target = args.target
    target_ip = socket.gethostbyname(target)
    counters["target_ip"] = target_ip

    bpf_filter = f"icmp and host {target_ip}"

    # run sniff() in a background thread so Rich can update freely
    sniffer = threading.Thread(
        target=sniff,
        kwargs={"prn": process_packet, "store": 0, "timeout": DURATION,"filter": bpf_filter},
        daemon=True
    )

    pinger = threading.Thread(target = run_ping,args=(target,),daemon=True)

    sniffer.start()
    pinger.start()
    start = time.time()

    with Live(build_table(0,target), refresh_per_second=4, console=console) as live:
        while time.time() - start < DURATION:
            live.update(build_table(time.time() - start,target))
            time.sleep(0.25)

    sniffer.join()
    pinger.join()


    sent     = counters["sent"]
    received = counters["received"]
    loss     = max(0, sent - received)
    loss_pct = (loss / max(1, sent)) * 100

    summary = Table(title="Final Summary", border_style="green")
    summary.add_column("Metric", style="bold white",  justify="left")
    summary.add_column("Value",  style="bold green",  justify="right")

    summary.add_row("Target",          f"{target}  ({target_ip})")
    summary.add_row("Duration",        f"{DURATION}s")
    summary.add_row("Packets Sent",    str(sent))
    summary.add_row("Packets Received",str(received))
    summary.add_row("Packets Lost",    str(loss))
    summary.add_row("Packet Loss %",   f"{loss_pct:.1f}%")

    console.print(summary)

if __name__ == "__main__":
    main()
