# Alice "Allie" Roblee
# CYBR-260-45
# Provides a Censys API connector for ferromagnet
# Exposes the search function to abstract away the Censys API query

import time
from censys.search import CensysHosts
from censys.common.exceptions import CensysException


def search(query, CENSYS_API_ID, CENSYS_API_SECRET):
    """
    # function: search
    # purpose: Use the Censys API to search their database of internet scan data
    # inputs: The search query, a censys api id, and a censys api secret
    # returns: A dictionary of ip/port pairs found in the search results
    """
    ip_port_pairs = {}
    try:
        all_results = []
        count = 0
        cursor = None
        api = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)

        # Send API queries while there are still pages of results to get
        while True:
            results = api.search(query, cursor=cursor)

            # Append search results
            for result in results:
                all_results.extend(result)

            # Get the next result page cursor
            cursor = results.nextCursor
            if not cursor:
                break

            # Handle API rate limit
            time.sleep(2)

        # Extract the IP/Port pairs from the search results
        for host in all_results:
            ip = host['ip']
            count += 1
            services = host.get('services', [])
            if ip not in ip_port_pairs:
                ip_port_pairs[ip] = []
            for service in services:
                port = service['port']
                ip_port_pairs[ip].append(port)

        print(f'{count} Results From Censys Query - {query}')

    except CensysException as e:
        print(f"Error: {e}")

    return ip_port_pairs
