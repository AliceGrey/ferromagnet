# Alice "Allie" Roblee
# CYBR-260-45

import os
import sqlite3
import json
from connectors import shodan_api, censys_api, nmap_api

# Load the JSON data from the file
with open('config.json') as f:
    config = json.load(f)

# Import API keys
SHODAN_API_KEY = config["shodan"]["api_key"]
CENSYS_API_ID = config["censys"]["api_id"]
CENSYS_API_SECRET = config["censys"]["api_secret"]

# Censys search queries
CENSYS_QUERIES = [
    "services.service_name: COBALT_STRIKE",
    "services.certificate: { \"64257fc0fac31c01a5ccd816c73ea86e639260da1604d04db869bb603c2886e6\" }",
    "services.certificate: { \"87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c\" }",
    "services.tls.certificates.leaf_data.issuer.common_name: \"Major Cobalt Strike\"",
    "services.tls.certificates.leaf_data.subject.common_name: \"Major Cobalt Strike\"",
    "services.tls.certificates.leaf_data.issuer.common_name: \"Pwn3rs Striked\"",
    "services.tls.certificates.leaf_data.subject.common_name: \"Pwn3rs Striked\""
]

# Shodan search queries
SHODAN_QUERIES = [
    "product:\"Cobalt Strike\"",
    "ssl:\"6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C\"",
    "hash:-2007783223 port:50050",
    "ssl.cert.subject.cn:\"Pwn3rs Striked\"",
    "ssl.cert.issuer.cn:\"Pwn3rs Striked\"",
    "ssl.cert.subject.cn:\"Major Cobalt Strike\"",
    "ssl.cert.issuer.cn:\"Major Cobalt Strike\"",
    "watermark:"
]


def dedupe_results(pages):
    """
    # function: dedupe_results
    # purpose: Deduplicate results in dictionary of search results
    # inputs: A dictionary containing IP/Port pairs from Shodan and Censys search results
    # returns: A deduplicated dictionary of IP/Port pairs
    """
    merged = {}
    # Iterate over each dictionary in the list
    for page in pages:
        # Iterate over each key-value pair in the current dictionary
        for key, value in page.items():
            # If the key already exists in the merged dictionary
            if key in merged:
                # If the value is not already a list, convert it to a list
                if not isinstance(merged[key], list):
                    merged[key] = [merged[key]]
                for port in value:
                    if port not in merged[key]:
                        # Append the port to the list if it doesn't already exist
                        merged[key].append(port)
            else:
                # If the key does not exist in the merged dictionary, add it
                merged[key] = value
    return merged

def main():
    """
    # function: main
    # purpose: Initialize database to store beacon data in, query APIs for possible beacons, then call nmap to scan for beacons and parse data
    # inputs: None
    # returns: Database of Cobalt Strike beacon configuration data
    """
    # Initialize SQLite database connection and cursor
    conn = sqlite3.connect('beacons.db')
    c = conn.cursor()
    # Get all possible Cobalt Strike config keys
    all_keys = nmap_api.all_keys
    # Column type overwrites
    column_types = {
        "seen_at": "DATETIME",
        "port": "INT"
    }

    all_columns = []
    for key in all_keys:
        # Select the column type that matches the column and default to text
        column_type = column_types[key] if key in column_types else "TEXT"
        all_columns.append(f'{key} {column_type}')

    # Create table
    table_gen = "CREATE TABLE IF NOT EXISTS beacons (" + ", ".join(all_columns) + ")"
    c.execute(table_gen)

    if 'DEBUG' in os.environ and os.path.exists('ip-port-pair-cache.json'):
            print('Loading IP/Port pairs from cache')
            with open('ip-port-pair-cache.json') as file:
                ip_port_pairs = json.loads(file.read())
    else:
        # Perform Shodan search
        print("Searching Shodan For Cobalt Strike")
        shodan_results = []
        for query in SHODAN_QUERIES:
            shodan_results.append(shodan_api.search(query, SHODAN_API_KEY))

        # Perform Censys search
        print("Searching Censys For Cobalt Strike")
        censys_results = []
        for query in CENSYS_QUERIES:
            censys_results.append(censys_api.search(query, CENSYS_API_ID, CENSYS_API_SECRET))

        all_results = shodan_results + censys_results
        # Merge results
        print("Merging Shodan and Censys Results")
        ip_port_pairs = dedupe_results(all_results)
    
        if 'DEBUG' in os.environ:
            with open('ip-port-pair-cache.json', 'wt') as file:
                file.write(json.dumps(ip_port_pairs))

    beacons = nmap_api.scan_for_cs_beacons(ip_port_pairs)

    # Insert data into the table
    question_marks = ["?"] * len(all_keys)
    insert_query = "INSERT INTO beacons VALUES (" + ", ".join(question_marks) + ")"
    for row in beacons:
       c.execute(insert_query, tuple(row.values()))

    # Commit changes and close connection
    conn.commit()
    conn.close()

    print(f"{len(beacons)} beacons inserted into SQLite database successfully.")

if __name__ == "__main__":
    main()