import nmap
from prettytable import PrettyTable

nmap_params = {'ips': '127.0.0.1', 'ports': '1-100', 'args': 'SYN' }
nmap_scan_types = {'SYN': '-sS', 'ACK': '-sA', 'FIN': '-sF', 'XMAS': '-sX'}


def validate_args(arg):
    if arg in nmap_scan_types.keys():
        return True
    else:
        return False


def validate_ports(ports):
    ports_list = ports.split('-')

    try:
        if ports_list and (len(ports_list) == 1 and int(ports_list[0])) or (len(ports_list) == 2 and int(ports_list[0]) and int(ports_list[1])):
            return True
        else:
            return False
    except:
        return False


def scan():
    ips = input('nmap> Enter IP address : ')
    if len(ips) > 0:
        nmap_params['ips'] = ips

    ports = input('nmap> Enter Port Range or Port (1-100 or 80) : ')
    if validate_ports(ports):
        nmap_params['ports'] = ports

    arg = input('nmap> Enter type of scan (ACK/XMAS/FIN/SYN) : ')
    if validate_args(arg):
        nmap_params['args'] = arg

    print("Press start/exit/show/set....")
    input_status = True
    while input_status:
        input_str = input('nmap> ')
        if input_str == 'exit':
            input_status = False
        elif input_str[0:3] == 'set':
            set_params(input_str)
        elif input_str == 'show':
            show()
        elif input_str == 'start':
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=nmap_params['ips'], ports=nmap_params['ports'], arguments=nmap_scan_types[nmap_params['args']])

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
        elif input_str != '':
            print('Invalid Input')


def set_params(input_str):
    error_status = False
    input_str = input_str[3:len(input_str)].strip()
    if input_str:
        param_list = input_str.split(' ')
        count = 0
        while count < len(param_list) and count+1 < len(param_list):
            if (param_list[count].lower() == 'ports' and validate_ports(param_list[count+1])) or\
                    (param_list[count].lower() == 'args' and validate_args(param_list[count+1].upper())) or\
                    param_list[count].lower() == 'ips':
                nmap_params[param_list[count].lower()] = param_list[count + 1].upper()
            else:
                error_status = True
            count += 2
    if error_status:
        print('Invalid Parameters')


def show():
    display_table = PrettyTable(['Parameters', 'Values'])
    display_table.add_row(['IPs', nmap_params['ips']])
    display_table.add_row(['Ports', nmap_params['ports']])
    display_table.add_row(['Args', nmap_params['args']])
    print(display_table)

