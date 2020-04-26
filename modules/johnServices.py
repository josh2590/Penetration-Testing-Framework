# Using JOhn the ripper to crack the password. To use this utility either install john or use Kali OS
import os
from subprocess import call


def passwordCrack():
    wordlist = input('john> enter the path of wordlist : ')
    hash = input('john> enter the path of hash file or hash : ')

    if os.path.exists(wordlist):
        output = call(['john', '--wordlist='+wordlist, hash])
    else:
        output = call(['john', hash])
    print(output)