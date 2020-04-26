from prettytable import PrettyTable
from modules import networkSniffer, nmapServices, runningService

print("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>")
print("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>")
print("<<<< Penetration Testing Tools >>>>")
print("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>")
print("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>")
print()
display_menu = PrettyTable(['', 'Tools'])
display_menu.add_row(['1.', 'Network Sniffer'])
display_menu.add_row(['2.', 'Host Services Scan'])
display_menu.add_row(['3.', 'IP/Port Scanner'])
display_menu.add_row(['4.', 'Password Cracker'])
display_menu.add_row(['5.', 'Vulnerability Scanner'])
display_menu.add_row(['6.', 'OSINT'])
print('NOTE : Option 4/5/6 are currently not available.')
print('')
print('Enter your choice (1/2/3/4/5/6)...Press \'exit\' to close')
print(display_menu)

input_status = True
while input_status:
    input_str = input('pen-tools> ')
    if input_str == 'exit':
        input_status = False
    elif input_str == '1':
        networkSniffer.sniffer()
    elif input_str == '2':
        runningService.scan()
    elif input_str == '3':
        nmapServices.scan()
    elif input_str == '4':
        print('Sorry! Option not available')
    elif input_str == '5':
        print('Sorry! Option not available')
    elif input_str == '6':
        print('Sorry! Option not available')
    elif input_str != '':
        print('Invalid Input !!')
