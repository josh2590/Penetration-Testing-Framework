import os
import threading
import time
import netifaces
from pylibpcap import sniff
from prettytable import PrettyTable

ns_options_list = ['show', 'help', 'start', 'stop']
ns_help = 'This is a network sniffer tool designed to record the network packets. \n Press \'help\' to get more ' \
          'information about this tool......... \n Use following commands for network sniffing : \n     start : to ' \
          'start the network sniffing \n     set : to set values of parameters' \
          '\n     stop : to end the network sniffing \n     show : to display set values of parameters' \
          '\n Use following parameter to pass with \'start\' commands :\n' \
          '     -o <path> : to pass the output path for file\n     -t <seconds>: to stop the sniffing after given time' \
          '\n     -d : to display the sniffing on console\n     -v : to verbose the logs\n     -i : to pass the ' \
          'network interface \n Use set (o/t/d/v/i) <value> to set the parameters. \n      set d true i eth0'

params = {}
ns_start_params_list = ['o', 't', 'd', 'v', 'i']
ns_invalid_input_error = 'Invalid input !!!!...... Use \'help\' to get more information.'
ns_invalid_param_error = 'Invalid parameter !!!! Use \'help\' to get more information.'
ns_invalid_path_error = 'Invalid output path !!!! Use \'help\' to get more information.'
ns_invalid_interface_error = 'Invalid interface !!!! Use \'help\' to get more information.'

# Default values for the parameters
ns_verbose_status = 'false'
ns_display_status = 'false'
ns_stop_status = False
BUFFER_SIZE = 65565
file = 'network_data.pcap'
output_path = '/usr/local/bin/'
interface = 'eth0'
time_duration = 10


def ns_display():
    display_table = PrettyTable(['Parameters', 'Values'])
    display_table.add_row(['Interface', params['i']])
    display_table.add_row(['Output Path', params['o']])
    display_table.add_row(['Time <in secs>', params['t']])
    display_table.add_row(['Verbose', params['v']])
    display_table.add_row(['Display Sniffing', params['d']])
    print(display_table)


def default_params():
    global params
    params['o'] = output_path
    params['t'] = time_duration
    params['d'] = ns_display_status
    params['v'] = ns_verbose_status
    params['i'] = interface


def set_params(input_str):
    error_status = False
    input_str = input_str[3:len(input_str)].strip()
    if input_str:
        param_list = input_str.split(' ')
        count = 0
        while count < len(param_list) and count+1 < len(param_list):
            if param_list[count] in ns_start_params_list and validate_param_type(param_list[count],
                                                                                 param_list[count + 1]):
                params[param_list[count]] = param_list[count + 1]
            else:
                error_status = True
            count += 2
    if error_status:
        print(ns_invalid_input_error)


def sniffer():
    default_params()
    input_status = True
    while input_status:
        input_str = input('network-sniffer> ')
        if input_str == 'exit':
            input_status = False
        elif input_str[0:5] == 'start' and validate_args_param(input_str):
            start_sniffer()
        elif input_str[0:3] == 'set':
            set_params(input_str)
        elif input_str == 'stop':
            stop_sniffer()
        elif input_str == 'help':
            print(ns_help)
        elif input_str == 'show':
            ns_display()
        elif input_str != '' and input_str not in ns_options_list:
            print(ns_invalid_input_error)
        else:
            pass


# This module will validate the type of input params
def validate_param_type(param, value):
    try:
        if (param == 'i' and value in netifaces.interfaces()) or \
                (param == 'o' and os.path.exists(value)) or \
                (param == 't' and int(value)) or \
                ((param == 'v' or param == 'd') and value.lower() in ('t', 'f', 'true', 'false', '1', '0')):
            return True
        else:
            return False
    except:
        return False


# This module will check the validity of entered parameters
def validate_args_param(input_str):
    global params
    status = True
    input_str = input_str[5:len(input_str)].strip()
    if input_str:
        param_list = input_str.split('-')
        for param in param_list:
            if param:
                param_pair = param.strip().split(' ')
                if param_pair[0] in ns_start_params_list and len(param_pair) == 2 and \
                        validate_param_type(param_pair[0].strip(), param_pair[1].strip()):
                    params[param_pair[0].strip()] = param_pair[1].strip()
                else:
                    print(ns_invalid_param_error)
                    status = False
                    break
    return status


def validate_params():
    validate = True
    if params['i'] not in netifaces.interfaces():
        print('Interface is not valid')
        validate = False
    if not os.path.exists(params['o']):
        print('Output path is not exist')
        validate = False
    if not int(params['t']):
        print('Sniffing time is not valid')
        validate = False
    if params['v'] not in ('t', 'f', 'true', 'false', '1', '0'):
        print('Verbose state is not valid')
        validate = False
    if params['d'] not in ('t', 'f', 'true', 'false', '1', '0'):
        print('Display state is not valid')
        validate = False
    return validate


# Define a function for the thread for network sniffing
def network_sniff():
    current_time = time.time()
    if params['v'] in ('t', 'True', '1'):
        print("Starting Network Sniffing.....")
    for plen, t, buf in sniff(params['i'], count=-1, promisc=1, out_file=params['o'] + file):
        if params['d'] in ('t', 'True', '1'):
            print(buf)
        if time.time() > current_time + params['t'] or ns_stop_status:
            if params['v'] in ('t', 'True', '1'):
                print("Network Sniffing completed....")
            break


# Define a function for  network sniffing
def start_sniffer():
    if validate_params():
        try:
            # lock = threading.Lock();
            x = threading.Thread(target=network_sniff, args=(), daemon=True)
            x.start()
            print("network-sniffer>")
        except:
            print('Network Sniffing Failed')


# Define a function to stop network sniffing
def stop_sniffer():
    global ns_stop_status
    ns_stop_status = True
