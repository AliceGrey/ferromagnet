# Alice "Allie" Roblee
# CYBR-260-45
# Shodan api module
from shodan import Shodan
import math
import time

def search(query, SHODAN_API_KEY):
    ip_port_pairs = {}
    try:

        count = 0
        api = Shodan(SHODAN_API_KEY)

        total_pages = 1 # We always get at least one page
        page = 1
        while page <= total_pages:
            results = api.search(query, page=page)
            total_pages = math.ceil(results['total'] / 100)
            time.sleep(1)

            page += 1

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
