import nmap
from prettytable import PrettyTable


def scan_running_service():
    ip = input('nmap> Enter Ip address : ')
    port_range = input('nmap> Enter Port Range or Port (1-100 or 80) : ')
    nm = nmap.PortScanner()
    nm.scan(ip, port_range)

    try:
        if not nm.all_hosts():
            print('nmap> No Host Found....')
        for host in nm.all_hosts():
            print('nmap> Services running on', host)
            display_table = PrettyTable(['Service', 'Status', 'Port'])
            ports = ['tcp', 'udp']
            for port in ports:
                if port in nm[host]:
                    for port_number in nm[host][port]:
                        display_table.add_row([nm[host][port][port_number]['name'], nm[host][port][port_number]['state'], str(port_number)+'/'+port])

            print(display_table)
    except:
        print("nmap> Error in scanning services....")