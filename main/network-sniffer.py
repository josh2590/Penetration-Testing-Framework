import socket

ns_options_list = ['show', 'help', 'start']
ns_help = 'This is a network sniffer tool designed to record the network packets. \n Press \'help\' to get more ' \
          'information about this tool......... \n Use following commands for network sniffing : \n     start : to ' \
          'start the network sniffing' \
          '\n     end : to end the network sniffing \n Use following parameter to pass with \'start\' commands :\n' \
          '     -o <path> : to pass the output path for file\n     -t <seconds>: to stop the sniffing after given time'\
          '\n     -d : to display the sniffing on console\n     -v : to verbose the logs'

ns_start_args_list = ['o', 't', 'd', 'v']
ns_invalid_input_error = 'Invalid input !!!!...... Use \'help\' to get more information.'
ns_invalid_arg_error = 'Invalid argument !!!! Use \'help\' to get more information.'

ns_stop_status = False
BUFFER_SIZE = 65565


def ns_input():
    input_status = True
    while input_status:
        input_str = input('network-sniffer> ')
        if input_str == 'exit':
            input_status = False
        elif input_str[0:5] == 'start':
            start_sniffer(input_str)
        elif input_str == 'stop':
            stop_sniffer()
        elif input_str == 'help':
            print(ns_help)
        elif input_str not in ns_options_list:
            print(ns_invalid_input_error)
        else:
            print(input_str)
            pass


# This module will check the validity of entered arguments
def validate_arg(input_str):
    args = {}
    input_str = input_str[5:len(input_str)].strip()
    if input_str:
        arg_list = input_str.split('-')
        for arg in arg_list:
            if arg:
                arg_pair = arg.strip().split(' ')
                if arg_pair[0] in ns_start_args_list and len(arg_pair) == 2:
                    args[arg_pair[0].strip()] = arg_pair[1].strip()
                else:
                    args = {'error': ns_invalid_arg_error}
                    break
    return args


def start_sniffer(input_str):
    args = validate_arg(input_str)
    if 'error' in args:
        print(args['error'])
    else:
        try:
            socket_con = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            while not ns_stop_status:
                print(socket_con.recvfrom(BUFFER_SIZE))
        except socket.error:
            print('Failed to create socket')


def save():
    pass


def stop_sniffer():
    ns_stop_status = True
    # save the output
    save()

ns_input()
