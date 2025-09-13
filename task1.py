"""
Recon Tool (CLI & GUI)
----------------------
A cross-platform Python tool for automated reconnaissance and information gathering.
Features:
- WHOIS lookup (Windows: local executables, Linux: system whois)
- DNS record enumeration
- Subdomain enumeration (crt.sh, AlienVault, HackerTarget)
- Simple port scan (22, 80, 443)
- Banner grabbing
- Technology detection (HTTP headers)
- GUI interface (Tkinter)
- Saveable text reports

Usage:
- Run with Python 3.x: `python task1.py` (Windows) or `python3 task1.py` (Linux)
- Enter a domain (e.g., example.com) in the GUI and click "Run Recon"
- Save the report using the "Save Report" button

See README.md and INSTRUCTIONS.txt for more details.
"""

import re  # For cleaning URLs from user input

# Utility function to clean the target input (removes http:// or https:// if present)
def clean_target(target: str) -> str:
    """Remove http:// or https:// from the target if present.

    Args:
        target (str): The input domain or URL from the user.

    Returns:
        str: The cleaned domain name without protocol.
    """
    return re.sub(r'^https?://', '', target.strip(), flags=re.IGNORECASE)
#!/usr/bin/env python3
"""
Recon Tool (CLI & GUI)
This tool automates information gathering for penetration testing.
It can run WHOIS, DNS, subdomain enumeration, port scan, and technology detection
on a user-specified target domain, with both CLI and GUI interfaces.
"""


# Standard library imports
import subprocess  # For running external commands (like whois.exe)
import socket      # For DNS and port scanning
import json        # For formatting and saving results
import logging     # For logging with verbosity
import argparse    # For parsing command-line arguments
import sys         # For system exit and path
from datetime import datetime  # For timestamps
from pathlib import Path       # For file and path handling
from typing import Optional, Dict, List, Any  # For type hints


# Try to import tkinter for GUI mode; if not available, disable GUI
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


# Set up logging for the tool; verbose=True gives more detail
def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration for the tool.

    Args:
        verbose (bool): If True, set logging to DEBUG level; else INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


# Try to import optional dependencies for HTTP requests and DNS
try:
    import requests  # For web requests (subdomain APIs, tech detection)
except Exception:
    requests = None

try:
    import dns.resolver  # For advanced DNS queries
except Exception:
    dns = None



# ----------------- Utilities -----------------
def timestamp():
    """Return the current UTC time as a formatted string.

    Returns:
        str: Current UTC timestamp in 'YYYY-MM-DD HH:MM:SS UTC' format.
    """
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')


#################################################
# ----------------- WHOIS Module -----------------
#################################################
def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup for the given domain using available executables.

    Args:
        domain (str): The domain to look up.

    Returns:
        str: WHOIS output or error message.
    """
    # Try all possible whois executables (system and local)
    possible_paths = [
        "whois",  # Try system PATH first
        str(Path(__file__).parent / "Whois" / "whois.exe"),
        str(Path(__file__).parent / "Whois" / "whois64.exe"),
        str(Path(__file__).parent / "Whois" / "whois64a.exe"),
    ]
    last_error = None
    for path in possible_paths:
        try:
            # On Windows, shell=True is needed for PATH lookup, but not for direct .exe
            use_shell = path.lower() == "whois"
            out = subprocess.check_output(
                [path, domain],
                stderr=subprocess.STDOUT,
                timeout=20,
                shell=use_shell
            )
            # Try decoding with utf-8, fallback to latin1
            if isinstance(out, bytes):
                try:
                    out = out.decode('utf-8')
                except Exception:
                    out = out.decode('latin1', errors='replace')
            return out  # Return the WHOIS output
        except FileNotFoundError:
            last_error = f"WHOIS executable not found: {path}"
            continue
        except subprocess.CalledProcessError as e:
            last_error = f"WHOIS command failed with {path}:\n{e.output}"
            continue
        except Exception as e:
            last_error = f"WHOIS lookup failed with {path}: {e}"
            continue
    # If all attempts fail, return the last error
    return last_error or "WHOIS not available. Please install whois.exe or adjust path."

#################################################
# ----------------- DNS Module ------------------
#################################################
def dns_records(domain: str) -> dict:
    """Retrieve DNS records (A, MX, NS, TXT) for a domain.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: DNS records found for the domain.
    """
    # Prepare a dictionary for DNS record types
    records = {'A': [], 'MX': [], 'NS': [], 'TXT': []}
    if dns:
        # Use dnspython for advanced DNS queries if available
        resolver = dns.resolver.Resolver()
        for rtype in records.keys():
            try:
                answers = resolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    records[rtype].append(str(r).rstrip('.'))
            except Exception:
                pass  # Ignore errors for missing record types
    else:
        # Fallback: only get A records using socket
        try:
            a = socket.gethostbyname_ex(domain)
            if a and len(a) >= 3:
                records['A'] = a[2]
        except Exception:
            pass
    return records


#########################################################
# ----------------- Subdomain Module -------------------
#########################################################
def get_subdomains_from_source(domain: str, source: str) -> set:
    """Query a specific source for subdomains of a domain.

    Args:
        domain (str): The domain to enumerate.
        source (str): The data source (crtsh, alienvault, hackertarget).

    Returns:
        set: Subdomains found from the source.
    """
    subs = set()  # Set to store found subdomains
    if not requests:
        return subs  # If requests is not available, skip
    try:
        if source == 'crtsh':
            # Query crt.sh for certificate transparency subdomains
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value')
                    if name:
                        for n in name.split('\n'):
                            subs.add(n.strip())
        elif source == 'alienvault':
            # Query AlienVault OTX for passive DNS subdomains
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get('passive_dns', []):
                    if 'hostname' in entry:
                        subs.add(entry['hostname'])
        elif source == 'hackertarget':
            # Query HackerTarget for hostsearch subdomains
            url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
            r = requests.get(url, timeout=15)
            if r.status_code == 200 and not r.text.startswith('error'):
                lines = r.text.split('\n')
                for line in lines:
                    if ',' in line:
                        hostname = line.split(',')[0]
                        if hostname.endswith(domain):
                            subs.add(hostname)
    except Exception as e:
        logging.debug(f"Error fetching from {source}: {str(e)}")
    return subs

def enumerate_subdomains(domain: str) -> dict:
    """Enumerate subdomains using multiple sources and validate them.

    Args:
        domain (str): The domain to enumerate.

    Returns:
        dict: Subdomain enumeration results, including validation.
    """
    all_subdomains = set()  # Collect all found subdomains
    sources = ['crtsh', 'alienvault', 'hackertarget']  # List of sources to use
    for source in sources:
        subs = get_subdomains_from_source(domain, source)
        logging.debug(f"Found {len(subs)} subdomains from {source}")
        all_subdomains.update(subs)
    # Validate and resolve subdomains (check if they resolve to an IP)
    results = {
        'total_found': len(all_subdomains),
        'sources_used': sources,
        'subdomains': {}
    }
    for sub in sorted(all_subdomains):
        try:
            ips = socket.gethostbyname_ex(sub)[2]
            results['subdomains'][sub] = {
                'status': 'active',  # DNS resolves
                'ips': ips
            }
        except socket.gaierror:
            results['subdomains'][sub] = {
                'status': 'inactive',  # DNS does not resolve
                'ips': []
            }
    return results


#########################################################
# ----------------- Simple Port Scan -------------------
#########################################################
def simple_port_scan(host: str, ports: list, timeout: float = 1.0) -> dict:
    """Scan a list of ports on a host to check if they are open or closed.

    Args:
        host (str): The IP address or hostname to scan.
        ports (list): List of port numbers to scan.
        timeout (float): Timeout for each port scan in seconds.

    Returns:
        dict: Port numbers mapped to 'open', 'closed', or error message.
    """
    results = {}  # Store port states
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)  # Set timeout for each port
            res = s.connect_ex((host, p))  # Try to connect
            state = 'open' if res == 0 else 'closed'
            results[p] = state
            s.close()
        except Exception as e:
            results[p] = f'error: {e}'  # Record error if any
    return results


#########################################################
# ----------------- Banner Grabbing --------------------
#########################################################
def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab the service banner from an open port.

    Args:
        host (str): The IP address or hostname.
        port (int): The port number.
        timeout (float): Timeout for the banner grab.

    Returns:
        str: The banner string, or empty if not found.
    """
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))  # Connect to the port
        try:
            s.sendall(b'\r\n')  # Send a newline to prompt a banner
        except Exception:
            pass
        try:
            data = s.recv(1024)  # Receive banner data
            return data.decode('utf-8', errors='replace').strip()
        finally:
            s.close()
    except Exception:
        return ''  # Return empty string if banner grab fails


#########################################################
# ----------------- Technology Detection ----------------
#########################################################
def detect_tech_http(host: str) -> dict:
    """Detect web technologies by analyzing HTTP headers and content.

    Args:
        host (str): The domain or IP to check.

    Returns:
        dict: Detected technology information.
    """
    info = {}  # Store detected info
    if not requests:
        return info  # If requests not available, skip
    for scheme in ('http://', 'https://'):
        try:
            url = scheme + host
            r = requests.get(url, timeout=6, allow_redirects=True)
            info['status_code'] = r.status_code  # HTTP status code
            info['server_header'] = r.headers.get('Server')  # Server header
            info['x_powered_by'] = r.headers.get('X-Powered-By')  # X-Powered-By header
            body = r.text[:2000].lower()  # First 2000 chars of body
            # Simple tech detection heuristics
            if 'wp-content' in body or 'wp-includes' in body:
                info.setdefault('detected', []).append('WordPress')
            if 'django' in (r.headers.get('X-Powered-By') or '').lower() or 'django' in body:
                info.setdefault('detected', []).append('Django')
            return info
        except Exception:
            continue  # Try next scheme if one fails
    return info


#########################################################
# ----------------- Reporting --------------------------
#########################################################
def generate_html_report(filename: Path, target: str, results: dict) -> None:
    """Generate a styled HTML report from scan results.

    Args:
        filename (Path): Output HTML file path.
        target (str): The scanned target.
        results (dict): The scan results to include in the report.
    """
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Recon Report - {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .section {{ margin-bottom: 20px; }}
            .section-title {{ background-color: #f0f0f0; padding: 10px; }}
            pre {{ background-color: #f8f8f8; padding: 10px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>Recon Report for {target}</h1>
        <p>Generated: {timestamp}</p>
        <hr>
        {content}
    </body>
    </html>
    '''
    sections = []
    for section, content in results.items():
        if isinstance(content, (dict, list)):
            content_str = json.dumps(content, indent=2, ensure_ascii=False)
        else:
            content_str = str(content)
        sections.append(f'''
        <div class="section">
            <h2 class="section-title">{section}</h2>
            <pre>{content_str}</pre>
        </div>
        ''')
    html_content = html_template.format(
        target=target,
        timestamp=timestamp(),
        content='\n'.join(sections)
    )
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_text_report(filename: Path, target: str, results: dict) -> None:
    """Generate a plain text report from scan results.

    Args:
        filename (Path): Output text file path.
        target (str): The scanned target.
        results (dict): The scan results to include in the report.
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f'Recon report for {target}\n')
        f.write(f'Generated: {timestamp()}\n')
        f.write('=' * 60 + '\n\n')
        for section, content in results.items():
            f.write(f'### {section}\n')
            if isinstance(content, (dict, list)):
                f.write(json.dumps(content, indent=2, ensure_ascii=False))
            else:
                f.write(str(content))
            f.write('\n\n')

def generate_report(filename: Path, target: str, results: dict) -> None:
    """Generate a report in either text or HTML format based on file extension.

    Args:
        filename (Path): Output file path.
        target (str): The scanned target.
        results (dict): The scan results to include in the report.
    """
    # Choose report format based on file extension
    if filename.suffix.lower() == '.html':
        generate_html_report(filename, target, results)
        logging.info(f"Generated HTML report: {filename}")
    else:
        generate_text_report(filename, target, results)
        logging.info(f"Generated text report: {filename}")


# ----------------- Orchestration -----------------


# ----------------- GUI -----------------
def gui_main():
    """Launch the GUI for the recon tool, allowing users to enter a domain, run scans, and save reports.

    The GUI is built with Tkinter and provides a user-friendly interface for all recon features.
    """
    scan_results = {'data': None, 'target': None}  # Dictionary to store scan results and target

    # --- GUI Widgets Setup ---
    root = tk.Tk()  # Create the main application window
    root.title("Recon Tool (GUI)")  # Set the window title

    frm = ttk.Frame(root, padding=10)  # Create a frame with padding
    frm.pack(fill=tk.BOTH, expand=True)  # Add the frame to the window and allow it to expand

    lbl_target = ttk.Label(frm, text="Target Domain or URL:")  # Label for the target input
    lbl_target.pack(anchor=tk.W)  # Place the label at the top left

    entry_target = ttk.Entry(frm, width=50)  # Entry widget for user to input the target
    entry_target.pack(fill=tk.X, pady=5)  # Add the entry to the frame with padding

    btn_run = ttk.Button(frm, text="Run Recon")  # Button to start the recon scan
    btn_run.pack(pady=5)  # Add the button to the frame with padding

    output_box = scrolledtext.ScrolledText(frm, width=80, height=25, font=("Consolas", 10))  # Output box for results
    output_box.pack(fill=tk.BOTH, expand=True, pady=5)  # Add the output box to the frame

    btn_save = ttk.Button(frm, text="Save Report")  # Button to save the report
    btn_save.pack(pady=5)  # Add the button to the frame with padding

    def on_run():
        """Run the reconnaissance scan and display results in the GUI."""
        target = entry_target.get().strip()  # Get the target from the entry box and remove whitespace
        if not target:
            messagebox.showwarning("Input needed", "Please enter a target domain.")  # Warn if input is empty
            return
        output_box.delete(1.0, tk.END)  # Clear the output box
        output_box.insert(tk.END, f"Running recon on {target}...\n\n")  # Show status
        root.update()  # Update the GUI
        results = {}  # Dictionary to store all results
        try:
            output_box.insert(tk.END, "Running WHOIS lookup...\n")  # Show status
            root.update()  # Update the GUI
            whois_result = whois_lookup(target)  # Run WHOIS lookup
            if not whois_result or whois_result.lower().startswith("whois not available"):
                whois_result = "WHOIS lookup failed or not available. Please ensure whois.exe is present."
            results['WHOIS'] = whois_result  # Store WHOIS result
            output_box.insert(tk.END, "Running DNS enumeration...\n")  # Show status
            root.update()  # Update the GUI
            results['DNS'] = dns_records(target)  # Run DNS record lookup
            output_box.insert(tk.END, "Running subdomain enumeration...\n")  # Show status
            root.update()  # Update the GUI
            results['Subdomains'] = enumerate_subdomains(target)  # Run subdomain enumeration
            output_box.insert(tk.END, "Running port scan...\n")  # Show status
            root.update()  # Update the GUI
            ports = [22, 80, 443]  # Ports to scan
            try:
                ip = socket.gethostbyname(target)  # Resolve the target to an IP address
                simple = simple_port_scan(ip, ports)  # Run a simple port scan
                results['PortScan'] = {'target_ip': ip, 'results': simple}  # Store port scan results
                banners_out = {}  # Dictionary to store banners
                for p, state in simple.items():  # For each port
                    if state == 'open':
                        banners_out[p] = grab_banner(ip, p)  # Grab the banner if port is open
                results['Banners'] = banners_out  # Store banners
            except Exception as e:
                results['PortScan'] = {
                    'target_ip': None,
                    'results': {p: 'unresolved (DNS failed)' for p in ports},
                    'error': f'Port scan failed: {str(e)}'
                }  # Store error if DNS fails
                results['Banners'] = {}  # No banners if DNS fails
            output_box.insert(tk.END, "Running technology detection...\n")  # Show status
            root.update()  # Update the GUI
            results['TechDetect'] = detect_tech_http(target)  # Run technology detection
            output_box.delete(1.0, tk.END)  # Clear the output box
            output_text = json.dumps(results, indent=2, ensure_ascii=False)  # Format results as JSON
            output_box.insert(tk.END, output_text)  # Display results
            scan_results['data'] = results  # Save results for later
            scan_results['target'] = target  # Save target for later
        except Exception as e:
            output_box.delete(1.0, tk.END)  # Clear the output box
            output_box.insert(tk.END, f"Error during reconnaissance: {str(e)}")  # Show error
            scan_results['data'] = None  # Clear results
            scan_results['target'] = None  # Clear target

    def on_save():
        """Save the reconnaissance results to a file."""
        if not scan_results['data'] or not scan_results['target']:
            messagebox.showwarning("No Data", "Run recon first before saving.")  # Warn if no data
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",  # Default file extension
            filetypes=[("Text Files", "*.txt")],  # File type filter
            initialfile=f"{scan_results['target']}_recon.txt"  # Default file name
        )
        if not file_path:
            return  # Do nothing if user cancels
        try:
            generate_text_report(Path(file_path), scan_results['target'], scan_results['data'])  # Save report
            messagebox.showinfo("Saved", f"Report saved to {file_path}")  # Show success message
        except Exception as e:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(scan_results['data'], indent=2, ensure_ascii=False))  # Save raw JSON if error
            messagebox.showinfo("Saved", f"Raw results saved to {file_path}")  # Show fallback message

    btn_run.config(command=on_run)  # Link the Run button to on_run
    btn_save.config(command=on_save)  # Link the Save button to on_save

    root.mainloop()  # Start the GUI event loop


# Main entry point: launch GUI if run directly and GUI is available
if __name__ == "__main__":
    if GUI_AVAILABLE:
        gui_main()
    else:
        print("tkinter is not available. GUI mode cannot be started.")
