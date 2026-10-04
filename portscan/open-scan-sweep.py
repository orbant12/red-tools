#!/usr/bin/env python3
"""
Open-Scan Sweep - Mass Open-Scan Scanner for HTB Pro Labs
Runs open-scan commands across multiple hosts to find open ports
"""

import argparse
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

print_lock = threading.Lock()

def print_color(message, color=Colors.RESET):
    """Thread-safe colored printing"""
    with print_lock:
        print(f"{color}{message}{Colors.RESET}")

def read_hosts(file_path):
    """Read hosts from file, one per line"""
    try:
        with open(file_path, 'r') as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return hosts
    except FileNotFoundError:
        print_color(f"[!] Error: File '{file_path}' not found", Colors.RED)
        sys.exit(1)
    except Exception as e:
        print_color(f"[!] Error reading file: {e}", Colors.RED)
        sys.exit(1)

def run_open_scan(host, additional_args, output_file=None, output_dir=None):
    """Run open-scan against a single host"""
    # Build the base command
    cmd = ['open-scan', host]
    
    # Add --open-ports flag (default behavior)
    if '--open-ports' not in additional_args and not any('--' in arg for arg in additional_args):
        cmd.append('--open-ports')
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)
    
    # Print separator and command info
    with print_lock:
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Scanning: {host}{Colors.RESET}")
        print(f"{Colors.MAGENTA}[*] Command: {' '.join(cmd)}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
    
    try:
        # Run command and show output in real-time
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        output_lines = []
        
        # Print output in real-time
        for line in process.stdout:
            with print_lock:
                print(line, end='')
            output_lines.append(line)
        
        process.wait(timeout=300)  # 5 minute timeout for port scanning
        output = ''.join(output_lines)
        
        # Save to individual file in directory if specified
        if output_dir:
            # Sanitize IP address for filename (replace . with _)
            safe_filename = host.replace('.', '_').replace(':', '_')
            individual_file = Path(output_dir) / f"{safe_filename}.txt"
            
            with print_lock:
                with open(individual_file, 'w') as f:
                    f.write(f"{'='*80}\n")
                    f.write(f"Host: {host}\n")
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Scan Date: {subprocess.check_output(['date']).decode().strip()}\n")
                    f.write(f"{'='*80}\n\n")
                    f.write(output)
        
        # Save to combined output file if specified (legacy support)
        if output_file:
            with print_lock:
                with open(output_file, 'a') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"Host: {host}\n")
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"{'='*80}\n")
                    f.write(output)
                    f.write("\n")
        
        # Print completion status
        with print_lock:
            if output_dir:
                safe_filename = host.replace('.', '_').replace(':', '_')
                print(f"{Colors.GREEN}[✓] Completed scan for {host} → {safe_filename}.txt{Colors.RESET}\n")
            else:
                print(f"{Colors.GREEN}[✓] Completed scan for {host}{Colors.RESET}\n")
        
        return (host, True, output)
        
    except subprocess.TimeoutExpired:
        process.kill()
        print_color(f"[!] {host} - Timeout (exceeded 5 minutes)", Colors.RED)
        return (host, False, "Timeout")
    except FileNotFoundError:
        print_color(f"[!] Error: 'open-scan' command not found. Make sure it's installed and in your PATH.", Colors.RED)
        sys.exit(1)
    except Exception as e:
        print_color(f"[!] {host} - Error: {e}", Colors.RED)
        return (host, False, str(e))

def main():
    banner = f"""{Colors.CYAN}
    ╔═══════════════════════════════════════╗
    ║   OPEN-SCAN SWEEP - Mass Scanner      ║
    ║     HTB Pro Labs Edition              ║
    ╚═══════════════════════════════════════╝
    {Colors.RESET}"""
    
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Run open-scan across multiple hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan with individual files per host
  python3 open-scan-sweep.py -f hosts-ip.txt -d scan_results/
  
  # With 10 concurrent threads and directory output
  python3 open-scan-sweep.py -f hosts-ip.txt -t 10 -d results/
  
  # Save to directory AND combined file
  python3 open-scan-sweep.py -f hosts-ip.txt -d scans/ -o all_results.txt
  
  # With custom open-scan arguments
  python3 open-scan-sweep.py -f hosts-ip.txt -d results/ -x '--top-ports' '100'
  
  # Full port scan with individual files
  python3 open-scan-sweep.py -f hosts-ip.txt -d full_scans/ -x '-p-'
        '''
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing IP addresses (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('-d', '--directory', help='Output directory to save individual results per host (e.g., scan_results/)')
    parser.add_argument('-o', '--output', help='Output file to save combined results (optional, use with -d or alone)')
    parser.add_argument('-x', '--extra-args', nargs='+', default=[], help='Additional arguments to pass to open-scan')
    
    args = parser.parse_args()
    
    # Read hosts
    hosts = read_hosts(args.file)
    print_color(f"[*] Loaded {len(hosts)} hosts from {args.file}", Colors.BLUE)
    
    # Create output directory if specified
    output_dir = None
    if args.directory:
        output_dir = Path(args.directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        print_color(f"[*] Individual results will be saved to: {output_dir}/", Colors.BLUE)
        print_color(f"[*] Files will be named: <IP_address>.txt (e.g., 10_10_110_5.txt)", Colors.CYAN)
    
    # Clear output file if it exists
    if args.output:
        Path(args.output).write_text("")
        print_color(f"[*] Combined results will also be saved to: {args.output}", Colors.BLUE)
    
    if not args.directory and not args.output:
        print_color(f"[*] No output specified. Results will only display on screen.", Colors.YELLOW)
        print_color(f"[*] Use -d <directory> for individual files or -o <file> for combined output.", Colors.YELLOW)
    
    print_color(f"[*] Starting scans with {args.threads} threads...", Colors.BLUE)
    print_color(f"[*] This may take a while depending on the number of hosts...\n", Colors.YELLOW)
    
    # Run scans with thread pool
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                run_open_scan, 
                host, 
                args.extra_args,
                args.output,
                output_dir
            ): host for host in hosts
        }
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print_color(f"[!] {host} - Exception: {e}", Colors.RED)
    
    # Print summary
    print_color(f"\n{'='*80}", Colors.BLUE)
    print_color("SCAN COMPLETE - SUMMARY", Colors.BOLD)
    print_color(f"{'='*80}", Colors.BLUE)
    print_color(f"Total hosts scanned: {len(hosts)}", Colors.CYAN)
    successful = sum(1 for _, success, _ in results if success)
    print_color(f"Completed: {successful}", Colors.GREEN)
    print_color(f"Failed/Timeout: {len(hosts) - successful}", Colors.RED)
    
    if args.directory:
        print_color(f"\n[*] Individual results saved to: {args.directory}/", Colors.GREEN)
        print_color(f"[*] You can view results with: ls -lh {args.directory}/", Colors.CYAN)
        print_color(f"[*] Or grep across all: grep -r 'open' {args.directory}/", Colors.CYAN)
    
    if args.output:
        print_color(f"\n[*] Combined results saved to: {args.output}", Colors.GREEN)
        print_color(f"[*] You can review the results with: cat {args.output}", Colors.CYAN)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_color("\n[!] Scan interrupted by user", Colors.YELLOW)
        sys.exit(0)
