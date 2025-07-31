import socket
import argparse
import os
import colorama
from colorama import Fore, init
init(autoreset=True)

default_ports = [
    20,21,22,23,25,53,67,68,69,80,
    110,123,135,137,138,139,143,161,162,389,
    443,445,465,514,587,631,993,995,1433,1521,
    1723,3306,3389,5432,5900,8080,8443,8888,79,
    106,111,113,515,554,873,902,989,990,1000
]

def parse_ports(ports_arg, all_ports=False):
    if all_ports:
        return list(range(0, 65536))
    if ports_arg is None:
        return default_ports
    elif "-" in ports_arg:
        start, end = map(int, ports_arg.split("-"))
        return list(range(start, end + 1))
    elif "," in ports_arg:
        return [int(p.strip()) for p in ports_arg.split(",")]
    else:
        return [int(ports_arg)]

def scan_ports(ip, ports, output_file=None, all_ports=False):
    if all_ports:
        print(Fore.YELLOW + f"Scanning {ip} on ALL 65536 ports...\n")
    else:
        print(Fore.YELLOW + f"Scanning {ip} on ports...\n")

    open_ports = []
    log_lines = [f"Scanning results for {ip}:\n"]

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            result = s.connect_ex((ip, port))
            if result == 0:
                message = f"[+] PORT {port} is OPEN"
                print(Fore.GREEN + message)
                open_ports.append(port)
                log_lines.append(message + "\n")
            s.close()
        except KeyboardInterrupt:
            msg = "Exiting scan"
            print(Fore.CYAN + f"\n{msg}")
            log_lines.append(msg + "\n")
            break
        except socket.gaierror:
            msg = "Hostname could NOT be resolved"
            print(Fore.RED + msg)
            log_lines.append(msg + "\n")
            break
        except socket.error:
            msg = "Couldn't connect to server"
            print(Fore.RED + msg)
            log_lines.append(msg + "\n")
            break

    print(Fore.CYAN + "\nScan complete.")
    if open_ports:
        result = "Open ports found: " + ", ".join(str(p) for p in open_ports)
        print(Fore.CYAN + result)
        log_lines.append(result + "\n")
    else:
        result = "No open ports found."
        print(Fore.CYAN + result)
        log_lines.append(result + "\n")

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.writelines(log_lines)
            abs_path = os.path.abspath(output_file)
            print(Fore.MAGENTA + f"\nResults saved to: {abs_path}")
        except Exception as e:
            print(Fore.RED + f"Failed to save results: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python-based port scanner")
    parser.add_argument("--ip", required=True, help="Target IP or Hostname")
    parser.add_argument("--ports", help="Port range (e.g. 20-100 or 80,443 or leave empty for 50 common ports)")
    parser.add_argument("--all", action="store_true", help="Scans all 65536 ports")
    parser.add_argument("--output", type=str, help="Save results to file")

    args = parser.parse_args()
    ports = parse_ports(args.ports, args.all)
    scan_ports(args.ip, ports, args.output, args.all)
