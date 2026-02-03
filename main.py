import threading
import socket
import subprocess
import queue
import sys
import logging
import platform
from datetime import datetime
from ipaddress import IPv4Network
import curses
from collections import defaultdict
import re
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.ERROR,  # Change from INFO to ERROR
    filename='network_scanner.log',  # Add log file
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

subnet = "192.168.1.0/24"
ports = queue.Queue()
hosts = queue.Queue()
results = {}
thread_count = 100

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "MSRPC",
    139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MYSQL", 3389: "RDP", 5900: "VNC"
}

class HostInfo:
    def __init__(self):
        self.os = "Unknown"
        self.services = {}
        self.ttl = None

class ScanDisplay:
    def __init__(self, stdscr, total_hosts):
        self.stdscr = stdscr
        self.total_hosts = total_hosts
        self.hosts_scanned = 0
        self.current_host = ""
        self.active_hosts = set()
        self.open_ports = defaultdict(list)
        self.status_message = ""
        self.host_info = {}

        # View mode and sorting
        self.view_mode = "list"  # "list" or "table"
        self.sort_column = "ip"  # "ip", "os", "ports"
        self.sort_reverse = False

        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)

        # Enable scrolling
        self.stdscr.scrollok(True)

    def update(self):
        try:
            self.stdscr.clear()
            max_y, max_x = self.stdscr.getmaxyx()
            y = 0

            # Header section
            header = f"Network Scanner - Subnet: {subnet}"
            if len(header) > max_x:
                header = header[:max_x-3] + "..."
            self.stdscr.addstr(y, 0, header, curses.A_BOLD)
            y += 1

            # Progress bar
            progress = (self.hosts_scanned / self.total_hosts) * 100
            progress_str = f"Progress: [{self.hosts_scanned}/{self.total_hosts}] {progress:.1f}%"
            self.stdscr.addstr(y, 0, progress_str)
            y += 1

            # View mode indicator
            view_indicator = f"View: {self.view_mode.upper()} | Sort: {self.sort_column.upper()} {'▼' if self.sort_reverse else '▲'} | [v] Toggle View | [i/o/p] Sort"
            if len(view_indicator) > max_x:
                view_indicator = view_indicator[:max_x-3] + "..."
            self.stdscr.addstr(y, 0, view_indicator, curses.color_pair(4))
            y += 2

            # Current activity
            if self.current_host:
                current_str = f"Currently scanning: {self.current_host}"
                if len(current_str) > max_x:
                    current_str = current_str[:max_x-3] + "..."
                self.stdscr.addstr(y, 0, current_str)
            y += 2

            # Render based on view mode
            if self.view_mode == "table":
                y = self._render_table_view(y, max_y, max_x)
            else:
                y = self._render_list_view(y, max_y, max_x)

            # Status message at the bottom
            if self.status_message and y < max_y:
                self.stdscr.addstr(max_y-1, 0, self.status_message, curses.color_pair(3))

            self.stdscr.refresh()

        except curses.error:
            pass

    def _render_list_view(self, y, max_y, max_x):
        """Render the traditional list view"""
        if self.active_hosts:
            self.stdscr.addstr(y, 0, "Active Hosts:", curses.A_BOLD)
            y += 1

            for host in sorted(self.active_hosts):
                if y >= max_y - 3:
                    break

                # Host line with OS info
                host_str = f"► {host}"
                if host in self.host_info:
                    info = self.host_info[host]
                    if info.os != "Unknown":
                        host_str += f" ({info.os})"

                if len(host_str) > max_x:
                    host_str = host_str[:max_x-3] + "..."
                self.stdscr.addstr(y, 0, host_str, curses.color_pair(1))
                y += 1

                # Port and service information
                ports = self.open_ports[host]
                if ports:
                    for port in sorted(ports):
                        if y >= max_y - 1:
                            break

                        service_str = f"   ├─ {port}"
                        if host in self.host_info and port in self.host_info[host].services:
                            service = self.host_info[host].services[port]
                            service_str += f" ({service['name']})"
                            if service['banner']:
                                banner = service['banner'].replace('\n', ' ')[:40]
                                service_str += f": {banner}"

                        if len(service_str) > max_x:
                            service_str = service_str[:max_x-3] + "..."

                        self.stdscr.addstr(y, 0, service_str, curses.color_pair(3))
                        y += 1
                y += 1
        return y

    def _render_table_view(self, y, max_y, max_x):
        """Render the table view with sortable columns"""
        if not self.active_hosts:
            return y

        # Table header
        header = f"{'IP Address':<15} │ {'Operating System':<20} │ {'Ports':<6} │ {'Services':<30}"
        if len(header) > max_x:
            header = header[:max_x-3] + "..."
        self.stdscr.addstr(y, 0, header, curses.A_BOLD | curses.color_pair(4))
        y += 1

        # Separator line
        separator = "─" * min(max_x - 1, len(header))
        self.stdscr.addstr(y, 0, separator, curses.color_pair(4))
        y += 1

        # Get sorted host data
        sorted_hosts = self._get_sorted_hosts()

        # Render each host as a table row
        for host in sorted_hosts:
            if y >= max_y - 1:
                break

            # Get host information
            os_info = "Unknown"
            if host in self.host_info:
                os_info = self.host_info[host].os

            ports = self.open_ports[host]
            port_count = len(ports)

            # Get top services
            services = []
            if ports:
                for port in sorted(ports)[:3]:  # Show top 3 services
                    service_name = COMMON_PORTS.get(port, str(port))
                    services.append(service_name)
            services_str = ", ".join(services)
            if len(ports) > 3:
                services_str += f" +{len(ports) - 3}"

            # Format row
            row = f"{host:<15} │ {os_info:<20} │ {port_count:<6} │ {services_str:<30}"
            if len(row) > max_x:
                row = row[:max_x-3] + "..."

            self.stdscr.addstr(y, 0, row, curses.color_pair(1))
            y += 1

        return y

    def _get_sorted_hosts(self):
        """Sort hosts based on current sort column and direction"""
        hosts_list = list(self.active_hosts)

        if self.sort_column == "ip":
            # Sort by IP address (convert to tuple of ints for proper sorting)
            hosts_list.sort(key=lambda ip: tuple(int(part) for part in ip.split('.')),
                          reverse=self.sort_reverse)
        elif self.sort_column == "os":
            # Sort by operating system
            hosts_list.sort(key=lambda ip: self.host_info.get(ip, HostInfo()).os,
                          reverse=self.sort_reverse)
        elif self.sort_column == "ports":
            # Sort by number of open ports
            hosts_list.sort(key=lambda ip: len(self.open_ports[ip]),
                          reverse=self.sort_reverse)

        return hosts_list

    def toggle_view(self):
        """Toggle between list and table view"""
        self.view_mode = "table" if self.view_mode == "list" else "list"
        self.update()

    def set_sort_column(self, column):
        """Set the sort column and toggle direction if already sorted by this column"""
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self.update()

    def update_host_info(self, ip, info):
        self.host_info[ip] = info

def get_ping_command(target_ip):
    """Get OS-specific ping command"""
    os_type = platform.system().lower()
    
    if os_type == "windows":
        return ["ping", "-n", "1", "-w", "1000", str(target_ip)]
    elif os_type == "darwin":  # macOS
        return ["ping", "-c", "1", "-W", "1", str(target_ip)]
    else:  # Linux and others
        return ["ping", "-c", "1", "-W", "1", str(target_ip)]

def ping_test(target_ip):
    try:
        logger.info(f"Pinging {target_ip}...")  # Changed from debug to info
        ping_cmd = get_ping_command(target_ip)
        logger.info(f"Using ping command: {' '.join(ping_cmd)}")  # Changed from debug to info
        
        ping = subprocess.Popen(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, error = ping.communicate(timeout=2)
        output_str = str(out)
        logger.debug(f"Ping output: {output_str}")
        
        # Check OS-specific success messages
        os_type = platform.system().lower()
        if os_type == "windows":
            return "TTL=" in output_str
        elif os_type == "darwin":  # macOS
            return "1 packets received" in output_str or "1 received" in output_str
        else:  # Linux and others
            return " 1 received" in output_str or "1 packets received" in output_str
            
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"Ping failed for {target_ip}: {str(e)}")
        if isinstance(ping, subprocess.Popen):
            ping.kill()
        return False

def port_scan(target_ip, port, display):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((str(target_ip), port))
        if result == 0:
            display.open_ports[str(target_ip)].append(port)
            display.update()
        s.close()
    except Exception as e:
        pass

def port_worker(display):
    while True:
        try:
            target_ip, port = ports.get_nowait()
            port_scan(target_ip, port, display)
            
            # If this was the last port for this host, analyze it
            remaining_ports = sum(1 for _ in ports.queue if _[0] == target_ip)
            if remaining_ports == 0 and str(target_ip) in display.active_hosts:
                host_ports = display.open_ports[str(target_ip)]
                analyze_host(str(target_ip), host_ports, display)
            
            ports.task_done()
        except queue.Empty:
            break

def host_worker(display):
    while True:
        try:
            target_ip = hosts.get_nowait()
            display.current_host = str(target_ip)
            display.update()
            
            if ping_test(target_ip):
                display.active_hosts.add(str(target_ip))
                display.update()
                for port in range(1, 1025):
                    ports.put((target_ip, port))
            
            display.hosts_scanned += 1
            display.update()
            hosts.task_done()
        except queue.Empty:
            break

def get_service_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send appropriate probe based on port
            if port == 80:
                s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH servers send banner automatically
            else:
                s.send(b"\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except:
        return None

def get_ping_output(ip):
    """Get ping output with TTL information"""
    try:
        ping_cmd = get_ping_command(ip)
        ping = subprocess.Popen(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        output, _ = ping.communicate(timeout=2)
        return output.lower()
    except:
        return ""

def detect_os(ip, ttl, open_ports):
    """Enhanced OS detection using TTL and port signatures"""
    os_type = "Unknown"
    
    # TTL-based detection
    if ttl:
        if ttl <= 64:
            os_type = "Linux/Unix"
        elif ttl <= 128:
            os_type = "Windows"
        elif ttl <= 255:
            os_type = "Cisco/Network Device"
    
    # Port signature detection
    if 3389 in open_ports:
        os_type = "Windows (RDP)"
    elif 22 in open_ports and 80 in open_ports:
        os_type = "Linux/Unix (SSH+HTTP)"
    elif 22 in open_ports:
        os_type = "Linux/Unix (SSH)"
    elif 445 in open_ports and 139 in open_ports:
        os_type = "Windows (SMB)"
    
    return os_type

def analyze_host(ip, ports, display):
    host_info = HostInfo()
    logger.info(f"Analyzing host {ip}...")
    
    # Get TTL from ping output
    ping_output = get_ping_output(ip)
    ttl_match = re.search(r"ttl=(\d+)", ping_output)
    if ttl_match:
        host_info.ttl = int(ttl_match.group(1))
        logger.info(f"Found TTL {host_info.ttl} for {ip}")
    
    # Detect OS using TTL and port signatures
    host_info.os = detect_os(ip, host_info.ttl, ports)
    logger.info(f"Detected OS for {ip}: {host_info.os}")
    
    # Get service banners for open ports
    for port in ports:
        service_name = COMMON_PORTS.get(port, "Unknown")
        banner = get_service_banner(ip, port)
        
        service_info = {"name": service_name, "banner": banner}
        host_info.services[port] = service_info
        logger.info(f"Port {port} on {ip}: {service_name} {banner if banner else ''}")
        
        # Update display with service information
        display.update_host_info(ip, host_info)
        display.update()

    return host_info

def get_subnet_input():
    while True:
        try:
            subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24): ").strip()
            # Validate subnet format
            IPv4Network(subnet)
            return subnet
        except ValueError as e:
            print(f"Invalid subnet format: {e}")
            print("Please use CIDR notation (e.g., 192.168.1.0/24)")

def input_handler(stdscr, display, scan_active):
    """Handle keyboard input in a separate thread"""
    stdscr.nodelay(True)  # Non-blocking input
    while scan_active[0] or True:  # Continue after scan for viewing results
        try:
            key = stdscr.getch()
            if key != -1:  # Key was pressed
                if key == ord('v') or key == ord('V'):
                    display.toggle_view()
                elif key == ord('i') or key == ord('I'):
                    display.set_sort_column('ip')
                elif key == ord('o') or key == ord('O'):
                    display.set_sort_column('os')
                elif key == ord('p') or key == ord('P'):
                    display.set_sort_column('ports')
                elif key == ord('q') or key == ord('Q'):
                    # User wants to quit
                    return
        except:
            pass
        threading.Event().wait(0.1)  # Small delay to prevent high CPU usage

def main(stdscr):
    # Get subnet from user before initializing curses
    curses.endwin()  # Temporarily exit curses mode
    subnet = get_subnet_input()

    # Re-initialize curses
    stdscr.refresh()
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(True)  # Enable non-blocking input

    network = IPv4Network(subnet)
    total_hosts = sum(1 for _ in network.hosts())
    display = ScanDisplay(stdscr, total_hosts)

    # Update the display with chosen subnet
    display.status_message = f"Starting scan of subnet: {subnet} | Press 'v' to toggle view, 'i/o/p' to sort, 'q' to quit"
    display.update()

    start_time = datetime.now()

    # Flag to track scan status
    scan_active = [True]

    # Start input handler thread
    input_thread = threading.Thread(target=input_handler, args=(stdscr, display, scan_active))
    input_thread.daemon = True
    input_thread.start()

    # Add hosts to queue
    for ip in network.hosts():
        hosts.put(ip)

    # Start host discovery threads
    host_threads = []
    for _ in range(min(thread_count, hosts.qsize())):
        t = threading.Thread(target=host_worker, args=(display,))
        t.start()
        host_threads.append(t)

    # Wait for host discovery to complete
    for t in host_threads:
        t.join()

    # Start port scanning threads
    port_threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=port_worker, args=(display,))
        t.start()
        port_threads.append(t)

    # Wait for port scanning to complete
    for t in port_threads:
        t.join()

    end_time = datetime.now()
    duration = end_time - start_time
    scan_active[0] = False

    display.status_message = f"Scan completed in {duration} | Press 'v' to toggle view, 'i/o/p' to sort, 'q' to quit"
    display.update()

    # Wait for user to quit
    stdscr.nodelay(False)  # Make getch blocking
    while True:
        key = stdscr.getch()
        if key == ord('v') or key == ord('V'):
            display.toggle_view()
        elif key == ord('i') or key == ord('I'):
            display.set_sort_column('ip')
        elif key == ord('o') or key == ord('O'):
            display.set_sort_column('os')
        elif key == ord('p') or key == ord('P'):
            display.set_sort_column('ports')
        elif key == ord('q') or key == ord('Q'):
            break

if __name__ == "__main__":
    curses.wrapper(main)