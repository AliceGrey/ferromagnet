# Alice "Allie" Roblee
# CYBR-260-45
# Provides a Shodan API connector for ferromagnet
# Exposes the search function to abstract away the Shodan API query

from shodan import Shodan
import math
import time


def search(query, SHODAN_API_KEY):
    """
    # function: search
    # purpose: Use the Shodan API to search their database of internet scan data
    # inputs: The search query, and a shodan api key
    # returns: A dictionary of ip/port pairs found in the search results
    """
    ip_port_pairs = {}
    try:
        count = 0
        total_pages = 1  # We always get at least one page
        page = 1
        api = Shodan(SHODAN_API_KEY)

        while page <= total_pages:
            results = api.search(query, page=page)
            # Calculate the total number of pages based on each page having no more than 100 results.
            total_pages = math.ceil(results['total'] / 100)
            # Handle API rate limit
            time.sleep(1)

            page += 1

            # Extract the IP/Port pairs from the search results
            for result in results['matches']:
                ip = result['ip_str']
                count += 1
                if ip not in ip_port_pairs:
                    ip_port_pairs[ip] = []
                port = result['port']
                ip_port_pairs[ip].append(port)

        print(f"{count} Results From Shodan Query - {query}")

    except KeyError as e:
        print('Error: {}'.format(e))

    return ip_port_pairs
