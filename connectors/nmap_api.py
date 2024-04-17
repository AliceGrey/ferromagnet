# Alice "Allie" Roblee
# CYBR-260-45

import json
import subprocess
import xmltodict
import queue
import threading
import os
import json

# All potential Cobalt Strike Config Keys With (x86/x64) Prefix
keys_to_check = [
    'sha256', 'sha1', 'uri_queried', 'md5', 'time', 'beacon_type', 'port', 'polling', 'jitter', 'c2_server',
    'spawn_to_x86', 'spawn_to_x64', 'watermark', 'c2_host_header',
    'max_dns', 'user_agent', 'http_method_path_2', 'header_1', 'header_2',
    'injection_process', 'pipe_name', 'year', 'month', 'day', 'dns_idle',
    'dns_sleep', 'method_1', 'method_2', 'proxy_hostname', 'proxy_username',
    'proxy_password', 'proxy_access_type', 'create_remote_thread'
]

# Singular Scan Result Keys
all_keys = [
    'seen_at', 'ip', 'hostnames', 'protocol', 'port', 'service'
]
# Add x86 and x64 keys to all_keys
for key in keys_to_check:
    all_keys.append(f'x64_{key}')
    all_keys.append(f'x86_{key}')


class Worker(threading.Thread):
    """
    # class: Worker
    # purpose: Define custom thread class
    # inputs: The queue of hosts to scan
    # returns: The Cobalt Strike beacons found
    """

    def __init__(self, host_queue, host_count):
        """
        # function: __init__
        # purpose: Initialize all worker variables
        # inputs: The queue of hosts and the number of hosts in the queue at the start
        # returns: None
        """
        # Call threading.Thread.__init__() to initialize the parent thread class
        super().__init__()

        self.host_queue = host_queue
        self.host_count = host_count
        self.all_keys = all_keys
        self.beacons = []

    def run(self):
        """
        # function: run
        # purpose: Define work to be done in the thread
        # inputs: none
        # returns: none
        """
        # Loop until the queue is empty
        while True:
            try:
                host = self.host_queue.get_nowait()
            except queue.Empty:
                break

            # Calculate the number of hosts removed from the queue so far
            hosts_finished = self.host_count - self.host_queue.qsize()

            # Extract host information from tuple
            (ip, port_list) = host
            port_list = map(str, port_list)
            
            # Define custom nmap command
            cmd = ['nmap', ip, '-p', ','.join(port_list), '--script', 'grab_beacon_config.nse', '-vv', '-d', '-n', '-Pn', '-T3', '-oX', '-']
            print(f'Thread {self.native_id} - Scan {hosts_finished}/{self.host_count}: Running command {" ".join(cmd)}')

            # Execute nmap command in subprocess
            nmap_cmd_result = subprocess.run(cmd, capture_output=True, text=True)
            # Convert nmap xml output to python dict
            nmap_result_dict = xmltodict.parse(nmap_cmd_result.stdout)
            # Parse dict to extract Beacon config data we care about
            parsed_result = parse_nmap_output(nmap_result_dict)
            if parsed_result is not None:
                self.beacons.append(parsed_result)


def scan_for_cs_beacons(ip_port_pairs):
    """
    # function: scan_for_cs_beacons
    # purpose: Use threading to scan for cobalt strike beacons
    # inputs: The list of (ip, [port]) tuples to process
    # returns: All beacons found
    """
    
    # Cache beacon data for debug mode
    if 'DEBUG' in os.environ:
        if os.path.exists('beacon-cache.json'):
            print('Loading beacons from cache')
            with open('beacon-cache.json') as file:
                return json.loads(file.read())
    
    
    host_queue = queue.Queue()
    print(f'Queueing up {len(ip_port_pairs)} IPs')
    
    # Add hosts to the queue of work to be done
    for host in ip_port_pairs.items():
        host_queue.put(host)

    # Maximum number of workers running at one time
    NUM_WORKERS = 5
    workers = [] 

    # Create the worker thread objects
    for _ in range(NUM_WORKERS):
        workers.append(Worker(host_queue, len(ip_port_pairs)))

    # Start each worker thread
    for worker in workers:
        worker.start()

    # Wait for all worker threads to finish, and combine all their beacon data
    all_beacons = []
    for worker in workers:
        worker.join()
        all_beacons += worker.beacons
    
    # Write to beacon-cache if debug mode is enabled
    if 'DEBUG' in os.environ:
        with open('beacon-cache.json', 'wt') as file:
            file.write(json.dumps(all_beacons))

    return all_beacons


def parse_nmap_output(result):
    """
    # function: parse_nmap_output
    # purpose: Parse the dictionary that was converted from the nmap XML output
    # inputs: Dictionary of an nmap scan result
    # returns: All beacon configuration data that was found in the scan results
    """
    beacon = None
    parsed = {key: None for key in all_keys}
    # Check if the host is online
    if result['nmaprun']['host']['status']['@state'] != 'up':
        return None

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
        return None

    # Check that we actually got the x86/x64 beacons
    has_x86 = 'x86_port' in beacon.keys()
    has_x64 = 'x64_port' in beacon.keys()

    # If we didn't get either, bail out
    if not has_x86 and not has_x64:
        return None
    
    # Loop over all config values we got from Nmap
    for key, value in beacon.items():

        # If key exists, save value
        if key in all_keys:
            parsed[key] = value
    
    # Set the base nmap values not from the NSE
    parsed['seen_at'] = result['nmaprun']['runstats']['finished']['@time']
    parsed['ip'] = result['nmaprun']['host']['address']['@addr']
    parsed['hostnames'] = result['nmaprun']['host']['hostnames']
    parsed['protocol'] = beacon['port']['@protocol']
    parsed['port'] = beacon['port']['@portid']

    if 'service' in beacon['port']:
        parsed['service'] = beacon['port']['service']['@name']

    return parsed
