#!/usr/bin/env python3
"""
Fast port scanner using netcat (nc) - optimized for proxychains
Usage: portscan.py <target> [options]
"""

import subprocess
import sys
import argparse
import concurrent.futures
from typing import List, Set
import signal

# Common ports to scan when using --open-ports
# Massive expanded list - 700+ ports covering virtually all common and uncommon services
COMMON_PORTS = [
    # Core Services (1-100)
    1, 5, 7, 9, 11, 13, 17, 18, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49,
    53, 67, 68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 95, 99,
    
    # Extended Core Services (100-200)
    101, 102, 104, 105, 107, 108, 109, 110, 111, 113, 115, 117, 118, 119,
    123, 135, 137, 138, 139, 143, 144, 161, 162, 163, 164, 174, 177, 178,
    179, 194, 199,
    
    # Additional Services (200-500)
    201, 202, 204, 206, 209, 210, 213, 218, 220, 259, 264, 280, 308, 311,
    318, 319, 320, 350, 351, 356, 366, 369, 370, 371, 383, 384, 387, 389,
    399, 401, 402, 427, 433, 434, 443, 444, 445, 464, 465, 475, 497, 500,
    
    # Services (500-1000)
    502, 504, 510, 512, 513, 514, 515, 517, 518, 520, 521, 522, 523, 524,
    525, 530, 531, 532, 533, 540, 542, 543, 544, 548, 550, 554, 556, 560,
    561, 563, 587, 591, 593, 623, 631, 636, 639, 646, 647, 648, 652, 654,
    665, 666, 674, 691, 692, 695, 698, 699, 700, 701, 702, 706, 711, 712,
    720, 749, 750, 782, 783, 800, 808, 829, 830, 831, 832, 833, 843, 847,
    848, 853, 860, 873, 888, 897, 898, 902, 903, 953, 981, 987, 989, 990,
    991, 992, 993, 994, 995, 999,
    
    # Services (1000-2000)
    1000, 1001, 1010, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1050,
    1058, 1059, 1080, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1098, 1099,
    1100, 1194, 1198, 1199, 1214, 1234, 1241, 1248, 1270, 1293, 1311, 1314,
    1337, 1344, 1352, 1381, 1417, 1433, 1434, 1494, 1500, 1501, 1503, 1512,
    1513, 1521, 1522, 1524, 1527, 1533, 1534, 1540, 1541, 1581, 1582, 1583,
    1604, 1645, 1646, 1666, 1677, 1701, 1716, 1720, 1723, 1755, 1801, 1812,
    1813, 1830, 1863, 1880, 1881, 1883, 1900, 1935, 1947, 1962, 1967, 1984,
    1985, 1998,
    
    # Services (2000-3000)
    2000, 2001, 2002, 2003, 2004, 2005, 2010, 2049, 2053, 2056, 2080, 2082,
    2083, 2086, 2087, 2095, 2096, 2100, 2101, 2102, 2103, 2104, 2105, 2121,
    2135, 2150, 2159, 2161, 2181, 2196, 2200, 2222, 2251, 2260, 2288, 2302,
    2323, 2345, 2368, 2369, 2370, 2375, 2376, 2379, 2380, 2399, 2404, 2433,
    2483, 2484, 2500, 2525, 2535, 2541, 2598, 2600, 2601, 2602, 2603, 2604,
    2605, 2606, 2628, 2638, 2701, 2702, 2710, 2800, 2809, 2811, 2947, 2967,
    2998, 2999,
    
    # Services (3000-4000)
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3020, 3050, 3052, 3074,
    3101, 3128, 3200, 3210, 3260, 3268, 3269, 3283, 3300, 3301, 3306, 3307,
    3333, 3351, 3380, 3386, 3389, 3396, 3412, 3423, 3478, 3479, 3480, 3493,
    3500, 3521, 3527, 3535, 3544, 3551, 3580, 3588, 3605, 3632, 3689, 3690,
    3702, 3724, 3784, 3785, 3799, 3804, 3814, 3826, 3827, 3835, 3868, 3872,
    3880, 3888, 3899, 3900, 3945, 3962, 3973, 3978, 3999,
    
    # Services (4000-5000)
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4089, 4096, 4111, 4125,
    4172, 4190, 4200, 4243, 4244, 4303, 4321, 4369, 4443, 4444, 4445, 4486,
    4500, 4534, 4567, 4569, 4600, 4662, 4664, 4672, 4711, 4713, 4728, 4730,
    4739, 4753, 4786, 4840, 4843, 4847, 4848, 4894, 4899, 4949, 4950, 5000,
    5001, 5002, 5003, 5004, 5005, 5009, 5010, 5011, 5025, 5050, 5051, 5060,
    5061, 5062, 5064, 5065, 5070, 5080, 5084, 5085, 5090, 5093, 5099, 5104,
    5151, 5154, 5172, 5190, 5200, 5214, 5221, 5222, 5223, 5228, 5229, 5269,
    5280, 5281, 5298, 5308, 5353, 5357, 5402, 5405, 5432, 5433, 5445, 5450,
    5480, 5481, 5495, 5498, 5499, 5500, 5501, 5517, 5550, 5554, 5555, 5556,
    5566, 5568, 5631, 5632, 5656, 5666, 5667, 5671, 5672, 5673, 5674, 5675,
    5680, 5688, 5700, 5718, 5719, 5720, 5721, 5722, 5723, 5724, 5741, 5742,
    5800, 5801, 5802, 5803, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907,
    5908, 5909, 5910, 5938, 5984, 5985, 5986, 5988, 5989, 5998, 5999,
    
    # Services (6000-7000)
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6050, 6051, 6064, 6065,
    6066, 6067, 6070, 6080, 6081, 6082, 6083, 6084, 6085, 6086, 6100, 6101,
    6110, 6111, 6112, 6123, 6129, 6156, 6200, 6209, 6222, 6251, 6262, 6346,
    6347, 6379, 6389, 6432, 6443, 6444, 6445, 6446, 6502, 6513, 6514, 6515,
    6543, 6547, 6566, 6600, 6619, 6622, 6653, 6660, 6661, 6662, 6663, 6664,
    6665, 6666, 6667, 6668, 6669, 6679, 6697, 6699, 6701, 6771, 6783, 6789,
    6831, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6901, 6969,
    
    # Services (7000-8000)
    7000, 7001, 7002, 7004, 7005, 7006, 7007, 7070, 7077, 7100, 7121, 7174,
    7200, 7201, 7210, 7272, 7280, 7281, 7391, 7402, 7426, 7443, 7473, 7474,
    7478, 7496, 7547, 7548, 7634, 7676, 7777, 7778, 7779, 7800, 7880, 7890,
    7915, 7920, 7921, 7937, 7938, 7999,
    
    # Services (8000-9000)
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011,
    8012, 8013, 8014, 8015, 8016, 8020, 8021, 8022, 8031, 8032, 8033, 8040,
    8042, 8045, 8074, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
    8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100,
    8101, 8102, 8111, 8112, 8118, 8123, 8139, 8140, 8161, 8172, 8180, 8181,
    8182, 8184, 8192, 8193, 8194, 8200, 8201, 8204, 8205, 8206, 8207, 8208,
    8222, 8243, 8280, 8281, 8282, 8291, 8292, 8293, 8300, 8301, 8302, 8333,
    8334, 8400, 8443, 8444, 8445, 8471, 8472, 8500, 8501, 8529, 8530, 8531,
    8554, 8555, 8600, 8649, 8651, 8652, 8691, 8765, 8766, 8767, 8787, 8793,
    8800, 8812, 8834, 8840, 8880, 8887, 8888, 8889, 8890, 8899, 8901, 8910,
    8911, 8912, 8913, 8989, 8990, 8991, 8997, 8998, 8999,
    
    # Services (9000-10000)
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9009, 9010, 9011, 9020, 9021,
    9022, 9023, 9024, 9025, 9026, 9027, 9043, 9050, 9051, 9060, 9080, 9081,
    9090, 9091, 9092, 9093, 9094, 9095, 9096, 9099, 9100, 9101, 9102, 9103,
    9119, 9160, 9191, 9200, 9201, 9300, 9301, 9418, 9443, 9444, 9500, 9535,
    9595, 9600, 9663, 9800, 9871, 9876, 9898, 9899, 9900, 9909, 9943, 9944,
    9981, 9991, 9997, 9998, 9999,
    
    # Services (10000-20000)
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009,
    10010, 10050, 10051, 10080, 10082, 10083, 10113, 10114, 10115, 10116,
    10128, 10160, 10161, 10162, 10200, 10215, 10260, 10389, 10443, 10554,
    10616, 10628, 10629, 11099, 11110, 11111, 11112, 11200, 11211, 11214,
    11215, 11319, 11320, 11321, 11367, 11371, 11720, 11751, 12012, 12013,
    12109, 12168, 12172, 12345, 12443, 12975, 12998, 13160, 13223, 13224,
    13400, 13720, 13721, 13724, 13782, 13783, 13785, 13786, 14000, 14141,
    14142, 14145, 14265, 14344, 15000, 15001, 15002, 15345, 15363, 15555,
    15567, 15672, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16161,
    16309, 16310, 16384, 16385, 16387, 16482, 16567, 16992, 16993, 17169,
    17185, 17200, 17235, 17500, 17777, 18000, 18080, 18081, 18091, 18092,
    18104, 18136, 18181, 18182, 18183, 18184, 18185, 18186, 18187, 18201,
    18206, 18300, 18301, 18333, 18444, 18888, 19000, 19150, 19283, 19315,
    19788, 19999,
    
    # Services (20000-30000)
    20000, 20011, 20012, 20031, 20101, 20111, 20171, 20222, 20547, 20560,
    20720, 21025, 21379, 21571, 21590, 21800, 21845, 22000, 22125, 22222,
    22273, 22347, 22350, 22555, 22763, 22800, 23053, 23294, 23333, 23399,
    23400, 23456, 23546, 24000, 24007, 24008, 24444, 24465, 24554, 24800,
    24842, 25000, 25001, 25565, 25672, 25826, 25999, 26000, 26001, 26214,
    26257, 26262, 26489, 26999, 27000, 27001, 27002, 27003, 27004, 27005,
    27010, 27015, 27016, 27017, 27018, 27019, 27036, 27037, 27374, 27500,
    27888, 27960, 28000, 28001, 28017, 28200, 28589, 29070, 29167, 29999,
    
    # Services (30000-40000)
    30000, 30001, 30002, 30003, 30100, 30301, 30400, 30999, 31336, 31337,
    31416, 31457, 31620, 31765, 31785, 32400, 32764, 32768, 32769, 32771,
    32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
    32782, 32783, 32784, 32785, 33033, 33060, 33434, 33848, 34443, 34567,
    34962, 34963, 34964, 35357, 36001, 36412, 37475, 37777, 38201, 38292,
    38293, 38865, 39681,
    
    # Services (40000-50000)
    40000, 40732, 41121, 41230, 41794, 41795, 42424, 43188, 43189, 43190,
    44321, 44444, 44818, 45000, 45054, 45678, 46823, 46824, 47001, 47557,
    47624, 47806, 47808, 48000, 48001, 48002, 48003, 48556, 49151, 49152,
    49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
    49165, 49167, 49175, 49176, 49400, 49999,
    
    # Services (50000+)
    50000, 50001, 50002, 50003, 50006, 50013, 50050, 50070, 50075, 50095,
    50100, 51000, 51010, 51103, 51235, 51413, 51493, 51554, 52673, 52822,
    52869, 53001, 54045, 54138, 54321, 55000, 55055, 55056, 55555, 55600,
    56737, 56738, 57294, 57797, 58080, 60000, 60020, 60443, 61532, 61613,
    61614, 61616, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
]

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Scan interrupted by user")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def scan_port(target: str, port: int, timeout: int = 2) -> bool:
    """
    Scan a single port using netcat
    Returns True if port is open, False otherwise
    """
    try:
        # Use nc with:
        # -z: zero-I/O mode (scanning)
        # -v: verbose (we'll capture this)
        # -w: timeout in seconds
        result = subprocess.run(
            ['nc', '-zv', '-w', str(timeout), target, str(port)],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )

        # nc outputs to stderr, check if connection succeeded
        output = result.stderr.lower()

        # Different versions of nc have different output formats
        if 'succeeded' in output or 'open' in output or 'connected' in output:
            return True

        return False

    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        return False

def scan_ports(target: str, ports: List[int], timeout: int = 2, max_workers: int = 10) -> Set[int]:
    """
    Scan multiple ports concurrently
    Returns set of open ports
    """
    open_ports = set()

    print(f"[*] Scanning {target}")
    print(f"[*] Ports to scan: {len(ports)}")
    print(f"[*] Timeout: {timeout}s")
    print(f"[*] Concurrent connections: {max_workers}")
    print("-" * 50)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }

        # Process results as they complete
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            completed += 1

            try:
                if future.result():
                    open_ports.add(port)
                    print(f"[+] Port {port} is OPEN")
            except Exception as e:
                pass

            # Progress indicator
            if completed % 10 == 0 or completed == len(ports):
                print(f"[*] Progress: {completed}/{len(ports)}", end='\r')

    print()  # New line after progress
    return open_ports

def parse_port_list(port_string: str) -> List[int]:
    """
    Parse port list string into list of port numbers
    Supports: 80,443,8080 or 80-100 or mix: 22,80-90,443
    """
    ports = []

    for part in port_string.split(','):
        part = part.strip()

        if '-' in part:
            # Range of ports
            try:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"[!] Invalid port range: {part}")
                continue
        else:
            # Single port
            try:
                ports.append(int(part))
            except ValueError:
                print(f"[!] Invalid port: {part}")
                continue

    return sorted(list(set(ports)))  # Remove duplicates and sort

def main():
    parser = argparse.ArgumentParser(
        description='Fast port scanner using netcat - optimized for proxychains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 --open-ports
  %(prog)s example.com -p 80,443,8080
  %(prog)s 10.0.0.1 -p 1-1000
  %(prog)s 192.168.1.1 -p 22,80-90,443,3389
  proxychains %(prog)s target.com --open-ports
  proxychains %(prog)s target.com -p 445,3389 -t 5 -w 5
        """
    )

    parser.add_argument('target', help='Target IP or hostname')

    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument(
        '-p', '--ports',
        help='Ports to scan (e.g., 80,443 or 1-1000 or 22,80-90,443)'
    )
    port_group.add_argument(
        '--open-ports',
        action='store_true',
        help='Scan common ports (700+ ports including uncommon services)'
    )

    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=2,
        help='Connection timeout in seconds (default: 2)'
    )

    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=10,
        help='Number of concurrent connections (default: 10, use lower with proxychains)'
    )

    args = parser.parse_args()

    # Determine which ports to scan
    if args.open_ports:
        ports = COMMON_PORTS
        print(f"[*] Scanning {len(ports)} common and uncommon ports")
    else:
        ports = parse_port_list(args.ports)

    if not ports:
        print("[!] No valid ports to scan")
        sys.exit(1)

    # Check if nc is available
    try:
        subprocess.run(['nc', '-h'], capture_output=True, timeout=1)
    except FileNotFoundError:
        print("[!] Error: 'nc' (netcat) not found. Please install it:")
        print("    Ubuntu/Debian: sudo apt install netcat-openbsd")
        print("    or: sudo apt install netcat-traditional")
        sys.exit(1)
    except Exception:
        pass  # nc -h might return non-zero, but that's ok

    # Run the scan
    open_ports = scan_ports(args.target, ports, args.timeout, args.workers)

    # Print results
    print("-" * 50)
    if open_ports:
        print(f"[+] Found {len(open_ports)} open port(s):")
        for port in sorted(open_ports):
            print(f"    {port}")
    else:
        print("[!] No open ports found")

    print("-" * 50)

if __name__ == '__main__':
    main()
