# Recon Tool (Python GUI)

A cross-platform reconnaissance tool for penetration testing, featuring a user-friendly GUI. It automates WHOIS, DNS, subdomain enumeration, port scanning, and technology detection for a given domain.

## Features
- GUI interface (Tkinter)
- WHOIS lookup (Windows: uses local executables, Linux: uses system whois)
- DNS record enumeration
- Subdomain enumeration (crt.sh, AlienVault, HackerTarget)
- Simple port scan (22, 80, 443)
- Banner grabbing
- Technology detection (HTTP headers)
- Saveable text reports

## Requirements
- Python 3.x
- `requests` and `dnspython` Python packages
- Tkinter (usually included with Python)
- On Windows: `Whois/` folder with whois executables
- On Kali Linux: `whois` installed (`sudo apt install whois`)

## Installation
1. Clone this repository:
   ```
   git clone <your-repo-url>
   cd <repo-folder>
   ```
2. (Optional) Create a virtual environment:
   - Windows: `python -m venv venv && venv\Scripts\activate`
   - Linux: `python3 -m venv venv && source venv/bin/activate`
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
- Run the tool:
  - Windows: `python task1.py`
  - Linux: `python3 task1.py`
- Enter a domain (e.g., `example.com`) and click "Run Recon".
- Save the report using the "Save Report" button.

See `INSTRUCTIONS.txt` for more details and troubleshooting.

## Sample Report
See `sample_report_example.com.txt` for a sample output.

## Docker (Bonus)
You can run the tool in a containerized environment:

```
docker build -t recon-tool .
docker run -it --rm recon-tool
```

> Note: GUI apps in Docker require X11 forwarding or a similar solution. For headless/CLI use, adapt the script accordingly.

## License
MIT
