#implement a password authentication system
#Author: E Parrish Miller, CSC 447

import sys
import getpass
import argon2
from argon2 import PasswordHasher
from password_strength import PasswordPolicy
#create file first time the script is run
file = open("users.db", "a")
file.close()
policy = PasswordPolicy.from_names(#https://pypi.org/project/password-strength/
    length=8,  # min length: 8
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
)

def createAccount():#create account sequence
    try:
        usr = sys.argv[2]
    except:
        print('Usage: ./pythenticator < -c | -l > username')
        exit(0)
    print('Creating user: ', usr)
    with open("users.db", "r") as file:
        for line in file:
            u, test  = line.strip().split(':')
            if u == usr:
                print('user already exists')
                exit(0)
    pw = getpass.getpass(prompt='Enter password for user {}:'.format(usr))#password prompt
    if not policy.test(pw):#policy.test() returns empty list if it passes
        ph = PasswordHasher()
        pwhash = ph.hash(pw)
        with open("users.db", "a") as file:
            file.write(usr)
            file.write(':')
            file.write(pwhash)
            file.write('\n')
            print('User creation successful')
    else:
        print('The password you entered does not meet the following requriements: ', policy.test(pw))

def login():
    try:
        usr = sys.argv[2]
    except:
        print('Usage: ./pythenticator < -c | -l > username')
        exit(0)
    pw = getpass.getpass()
    ph = PasswordHasher()
    with open("users.db", "r") as file:
        for line in file:
            name, pas = line.strip().split(':')
            if name == usr:
                try:
                    ph.verify(pas, pw)
                    print('Authentication Successful')
                except:
                    print('Username or Password Incorrect')

if __name__ == '__main__':
    if sys.argv[1] == '-c':
        createAccount()
    elif sys.argv[1] == '-l':
        login()
    else:
        print('Usage: ./pythenticator < -c | -l > username \n-c = create new user \n-l = login as user')



