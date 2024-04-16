# Alice "Allie" Roblee
# CYBR-260-45
# Censys api module

from censys.search import CensysHosts
from censys.common.exceptions import CensysException

def search(query, CENSYS_API_ID, CENSYS_API_SECRET):
    ip_port_pairs = {}
    try:
        count = 0
        api = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)

        all_results = []

        cursor = None
        while True:
            # print(f'{query} {cursor}')
            results = api.search(query, cursor=cursor)

            for result in results:
                all_results.extend(result)

            cursor = results.nextCursor
            if not cursor:
                break

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
