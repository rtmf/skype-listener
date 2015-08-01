# vim:sw=2:ts=2:noexpandtab
import requests
import time
import hashlib
import struct
from lxml import html
SWC_CMAG="578134"
SWC_LKID=b"msmsgs@msnmsgr.com"
SWC_LKEY=b"Q1P7W2E4J9R8U3S5"
SWC_MNUM=0x0E79A9C1
SWC_NAME="swx-skype.com"
SWC_VERS="908/1.5.108"
SWC_HMDV="client-s.gateway.messenger.live.com"
SWC_HLOG="login.skype.com"
SWC_HCON="api.skype.com"
SWC_HVID="vm.skype.com"
SWC_IPIE="pie"
SWC_IETM="etm"
SWC_ITOK="skypetoken"
SWC_IURI="//input[@name='%s']/@value"
PIE_MAGICK='"pie" value="'
ETM_MAGICK='"etm" value="'
TOKEN_MAGICK='"skypetoken" value="'

sc={}

def mshash(data):
	def little_endify(value, c_type="L"):
		return struct.unpack(">" + c_type, struct.pack("<" + c_type, value))[0]

	sha256_hash=hashlib.sha256(data+SWC_LKEY)

	sha256_digest = sha256_hash.digest()[0:16]
	# Make array of sha256 string ints
	sha256_integers = struct.unpack("<llll", sha256_digest)
	sha256_integers = [(x & 0x7fffffff) for x in sha256_integers]
	# Make array of chl string ints
	data += SWC_LKID
	amount = 8 - len(data) % 8
	data += b"".zfill(amount)
	chl_integers = struct.unpack("<%di" % (len(data)/4), data)
	# Make the key
	high = 0
	low = 0
	i = 0
	while i < len(chl_integers) - 1:
		temp = chl_integers[i]
		temp = (SWC_MNUM * temp) % 0x7FFFFFFF
		temp += high
		temp = sha256_integers[0] * temp + sha256_integers[1]
		temp = temp % 0x7FFFFFFF
		high = chl_integers[i + 1]
		high = (high + temp) % 0x7FFFFFFF
		high = sha256_integers[2] * high + sha256_integers[3]
		high = high % 0x7FFFFFFF
		low = low + high + temp
		i += 2
	high = little_endify((high + sha256_integers[1]) % 0x7FFFFFFF)
	low = little_endify((low + sha256_integers[3]) % 0x7FFFFFFF)
	key = (high << 32 ) + low
	key = little_endify(key, "Q")
	longs = [x for x in struct.unpack(">QQ", sha256_digest)]
	longs = [little_endify(x, "Q") for x in longs]
	longs = [x ^ key for x in longs]
	longs = [little_endify(abs(x), "Q") for x in longs]
	out = ""
	for value in longs:
		value = hex(value)
		value = value[2:-1]
		value = value.zfill(16)
		out += value.lower()
	return(str(out))

def subscribe():
	global sc
	print("subs...")
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"RegistrationToken":sc["rtok"],
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"Host":sc["hmsg"]
			}
	p={
			"interestedResources":[
				"/v1/users/ME/conversations/ALL/properties",
				"/v1/users/ME/conversations/ALL/messages",
				"/v1/users/ME/contacts/ALL",
				"/v1/threads/ALL"
				],
			"template":"raw",
			"channelType":"httpLongPoll"
			}
	r=requests.post('https://'+sc["hmsg"]+"/v1/users/ME/endpoints/SELF/subscriptions",json=p,headers=h)
	sc["cook"].update(r.cookies)

def getid():
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"X-Skypetoken":sc["st"],
			"X-Stratus-Caller":SWC_NAME,
			"X-Stratus-Request":"abcd1234",
			"Host":SWC_HCON
			}
	r=requests.get('https://'+SWC_HCON+'/users/self/displayname',headers=h,json={})
	j=r.json()
	print(j)
	sc["unam"]=j["username"]
	if("displayname" in j):
		sc["nick"]=j["displayname"]
	else:
		if("firstname" in j):
			sc["nick"]=j["firstname"]
		else:
			sc["nick"]=j["username"]

def subuser(u):
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"X-Skypetoken":sc["st"],
			"X-Stratus-Caller":SWC_NAME,
			"X-Stratus-Request":"abcd1234",
			"RegistrationToken":sc["rtok"],
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"Host":sc["hmsg"]
			}
	p={
			"contacts":{
				"id":"8:"+u
				}
			}
	r=requests.get('https://'+sc["hmsc"]+'/users/ME/contacts',headers=h,json={})
	
def authrq():
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"X-Skypetoken":sc["st"],
			"X-Stratus-Caller":SWC_NAME,
			"X-Stratus-Request":"abcd1234",
			"Host":SWC_HCON
			}
	r=requests.get('https://'+SWC_HCON+'/users/self/contacts/auth-request',headers=h,json={})
	j=r.json()
	print(j)
	for r in j:
		et=r["event_time"]
		sn=r["sender"]
		gr=r["greeting"]
		if (int(et)<=int(sc["tarq"])):
			continue
		r=requests.put('https://'+SWC_HCON+'/users/self/contacts/auth-request/'+sn+"/accept",headers=h,json={})
		subuser(sn)
			
def blist():
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"Accept-Encodings":"gzip",
			"Content-Type":"application/json",
			"X-Skypetoken":sc["st"],
			"X-Stratus-Caller":SWC_NAME,
			"X-Stratus-Request":"abcd1234",
			"Host":SWC_HCON
			}
	r=requests.get('https://'+SWC_HCON+'/users/self/contacts',headers=h,json={})
	j=r.json()
	print(j)
	for r in j:
		sn=r["skypename"]
		subuser(st)

def token():
	global sc
	print("rtok...")
	ct=str(int(time.time()))
	sha=mshash(bytes(ct,"latin-1"))
	h={
			"LockAndKey":"appId=" + str(SWC_LKID) + "; time=" + ct + "; lockAndKeyResponse="+sha,
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Authentication":"skypetoken="+sc["st"],
			"Content-Type":"application/json",
			"Connection":"close",
			"Accept":"*/*",
			"BehaviorOverride":"redirectAs404",
			"Host":sc["hmsg"]
			}
	if ("rtok" in sc):
			h["RegistrationToken"]=sc["rtok"]
	r=requests.post("https://"+sc["hmsg"]+"/v1/users/ME/endpoints",json={},headers=h,cookies=sc["cook"])
	sc["cook"].update(r.cookies)
	assert r.status_code>=200
	assert r.status_code<=201
	if("location" in r.headers):
		print("location moved")
		hnew=requests.utils.urlparse(r.headers["Location"]).netloc
		if (sc["hmsg"]!=hnew):
			sc["hmsg"]=hnew
			return token()
	rth=r.headers["Set-RegistrationToken"]
	rtl=requests.utils.parse_header_links(rth)[0]
	sc["rtok"]=rtl["url"]
	sc["rexp"]=rtl["expires"]
	sc["epid"]=rtl["endpointId"]
	subscribe()
	print("printing sc")
	print(sc["rtok"])

def link():
	print("link...")
	global sc
	token()
	url="https://%s/v1/users/ME/endpoints/%s/presenceDocs/messagingService"%(sc["hmsg"],sc["epid"])
	p={
			"id":"messagingService",
			"type":"EndpointPresenceDoc",
			"selfLink":"uri",
			"privateInfo":{
				"epname":"skype"
				},
			"publicInfo":{
				"capabilities":"",
				"typ":"1",
				"skypeNameVersion":SWC_VERS+"/"+SWC_NAME,
				"nodeInfo":"xx",
				"version":SWC_VERS
				}
			}
	s={
			"status":"Online"
			}
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"Content-Type":"application/json",
			"RegistrationToken":sc["rtok"],
			"Accept-Encodings":"gzip",
			"Host":sc["hmsg"]
			}
	r=requests.put("https://"+sc["hmsg"]+"/v1/users/ME/presenceDocs/messagingService",headers=h,json=s)
	print(r.status_code)
	print(r.headers)
	print(r.text)
	r=requests.put(url,headers=h,json=p)
	print(r.status_code)
	print(r.headers)
	print(r.text)
	sc["cook"].update(r.cookies)

def poll():
	global sc
	print("poll...")
	if (int(time.time())>int(sc["rexp"])):
		token()
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"RegistrationToken":sc["rtok"],
			"Content-Type":"application/json",
			"Accept-Encodings":"gzip"
			}
	r=requests.post('https://'+sc["hmsg"]+"/v1/users/ME/endpoints/SELF/subscriptions/0/poll",headers=h,data="")
	sc["cook"].update(r.cookies)
	j=r.json
	return r

def login(username,password):
	global sc
	sc["hmsg"]=SWC_HMDV
	sc["tarq"]=0
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Content-Type":"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
			"Connection":"close",
			"Accept":"*/*",
			"BehaviorOverride":"redirectAs404",
			"Host":SWC_HLOG
			}
	p={
			"method":"skype",
			"client_id":SWC_CMAG,
			"redirect_uri":"https://web.skype.com"
			}
	r=requests.get('https://'+SWC_HLOG+'/login',params=p,headers=h)
	assert r.status_code==200
	t=html.fromstring(r.text)
	sc["pie"]=t.xpath(SWC_IURI%SWC_IPIE)[0]
	sc["etm"]=t.xpath(SWC_IURI%SWC_IETM)[0]
	z=time.timezone
	if (z<0):
		z=-z
		zf='-'
	else:
		zf='+'
	zm=z/60
	zh=zm/60
	zm%=60
	p={
			"username":username,
			"password":password,
			"timezone_field":"%c|%d|%d"%(zf,zh,zm),
			"pie":sc["pie"],
			"etm":sc["etm"],
			"js_time":int(time.time()*1000),
			"client_id":SWC_CMAG,
			"redirect_uri":"https://web.skype.com/"
			}
	r=requests.post("https://"+SWC_HLOG+"/login",data=p)
	assert r.status_code==200
	t=html.fromstring(r.text)
	st=t.xpath(SWC_IURI%SWC_ITOK)
	if (len(st)>0):
		sc["st"]=st[0]
	else:
		#unhandled captcha
		return "CAPTCHA!"
	sc["cook"]=r.cookies
	token()
	getid()
	authrq()
	blist()
	poll()
	link()
	return "OK~"


print("hi")
login("rtmfaerie","OppaiDolly")
while 1:
	j=poll()
	time.sleep(1)
