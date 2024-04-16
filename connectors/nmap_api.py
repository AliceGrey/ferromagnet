# Alice "Allie" Roblee
# CYBR-260-45

import json
import subprocess
import xmltodict
import queue
import threading
from pprint import pprint

# All potential Cobalt Strike Config Keys With (x86/x64) Prefix
keys_to_check = [
    'sha256', 'sha1', 'uri_queried', 'md5', 'time', 'Beacon Type', 'Port', 'Polling', 'Jitter', 'C2 Server',
    'Spawn To x86', 'Spawn To x64', 'Watermark', 'C2 Host Header',
    'Max DNS', 'User Agent', 'HTTP Method Path 2', 'Header 1', 'Header 2',
    'Injection Process', 'Pipe Name', 'Year', 'Month', 'Day', 'DNS Idle',
    'DNS Sleep', 'Method 1', 'Method 2', 'Proxy Hostname', 'Proxy Username',
    'Proxy Password', 'Proxy Access Type', 'Create Remote Thread'
]

# Singular Scan Result Keys
all_keys = [
    'seen_at', 'ip', 'hostnames', 'protocol', 'port', 'service'
]
# Add x86 and x64 keys to all_keys
for key in keys_to_check:
    all_keys.append(f'x64_{key.lower().replace(" ", "_")}')
    all_keys.append(f'x86_{key.lower().replace(" ", "_")}')


class Worker(threading.Thread):

    def __init__(self, host_queue, host_count):
        super().__init__()

        self.host_queue = host_queue
        self.host_count = host_count
        self.all_keys = all_keys
        self.beacons = []

    def run(self):

        while True:
            try:
                host = self.host_queue.get_nowait()
            except queue.Empty:
                break

            hosts_remaining = self.host_count - self.host_queue.qsize()

            (ip, port_list) = host
            port_list = map(str, port_list)

            cmd = ['nmap', ip, '-p', ','.join(port_list), '--script', 'grab_beacon_config.nse', '-vv', '-d', '-n', '-Pn', '-T3', '-oX', '-']
            print(f'Thread {self.native_id} - Scan {hosts_remaining}/{self.host_count}: Running command {" ".join(cmd)}')

            nmap_cmd_result = subprocess.run(cmd, capture_output=True, text=True)
            nmap_result_dict = xmltodict.parse(nmap_cmd_result.stdout)
            parsed_result = parse_nmap_output(nmap_result_dict)
            if parsed_result is not None:
                self.beacons.append(parsed_result)


def scan_for_cs_beacons(ip_port_pairs):
    host_queue = queue.Queue()
    print(f'Queueing up {len(ip_port_pairs)} IPs')
    for host in ip_port_pairs.items():
        host_queue.put(host)

    NUM_WORKERS = 5
    workers = []

    for _ in range(NUM_WORKERS):
        workers.append(Worker(host_queue, len(ip_port_pairs)))

    for worker in workers:
        worker.start()

    all_beacons = []
    for worker in workers:
        worker.join()
        all_beacons += worker.beacons
    
    return all_beacons

def parse_nmap_output(result):
    beacon = None
    parsed = {key: None for key in all_keys}
    # Check if the host is online
    if result['nmaprun']['host']['status']['@state'] != 'up':
        return

    # Handle if more than one port was scanned
    if isinstance(result['nmaprun']['host']['ports']['port'], list):
        for port in result['nmaprun']['host']['ports']['port']:
            # Only parse if there is a beacon script response found
            if "script" in port:
                try:
                    if port['script']['@output'] == "No Valid Response":
                        continue
                    beacon = json.loads(port['script']['@output'])
                    beacon['port'] = port
                except Exception as e:
                    print(result['nmaprun']['host'])
                    print(port['script']['@output'])
                    print(e)
    # Handle if only one port was scanned
    else:
        # Only parse if there is a beacon script response found
        if "script" in result['nmaprun']['host']['ports']['port']:
            port = result['nmaprun']['host']['ports']['port']
            try:
                if port['script']['@output'] == "No Valid Response":
                    return
                beacon = json.loads(port['script']['@output'])
                beacon['port'] = port
            except Exception as e:
                print(result['nmaprun']['host'])
                print(port['script']['@output'])
                print(e)

    # Quit parsing if there isn't any beacon data
    if beacon is None:
        return

    parsed['seen_at'] = result['nmaprun']['runstats']['finished']['@time']
    parsed['ip'] = result['nmaprun']['host']['address']['@addr']
    parsed['hostnames'] = result['nmaprun']['host']['hostnames']
    parsed['protocol'] = beacon['port']['@protocol']
    parsed['port'] = beacon['port']['@portid']

    if 'service' in beacon['port']:
        parsed['service'] = beacon['port']['service']['@name']

    # if x86 beacon was found by Nmap
    if 'x86' in beacon:
        # Pull out all x86 config related key/value pairs
        config = beacon['x86']['config']
        # Loop over all config values we got from Nmap
        for key, value in config.items():
            # Convert key for dictionary flattening
            new_key = f'x86_{key.lower().replace(" ", "_")}'
            # If key exists, save value
            if new_key in all_keys:
                parsed[new_key] = value
    
    # if x64 beacon was found by Nmap
    if 'x64' in beacon:
        # Pull out all x64 config related key/value pairs
        config = beacon['x64']['config']
        # Loop over all config values we got from Nmap
        for key, value in config.items():
            # Convert key for dictionary flattening
            new_key = f'x64_{key.lower().replace(" ", "_")}'
            # If key exists, save value
            if new_key in all_keys:
                parsed[new_key] = value

    return parsed
