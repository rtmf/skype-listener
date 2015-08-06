# vim:sw=2:ts=2:noexpandtab
import requests
import time
import hashlib
import struct
import threading
from lxml import html
SWC_CMAG="578134"
SWC_LKID=b"msmsgs@msnmsgr.com"
SWC_LKEY=b"Q1P7W2E4J9R8U3S5"
SWC_MNUM=0x0E79A9C1
SWC_NAME="swx-skype.com"
SWC_VERS="908/1.7.251"
SWC_HMDV="client-s.gateway.messenger.live.com"
SWC_HLOG="login.skype.com"
SWC_HCON="api.skype.com"
SWC_HCNV="contacts.skype.com"
SWC_HVID="vm.skype.com"
SWC_IPIE="pie"
SWC_IETM="etm"
SWC_ITOK="skypetoken"
SWC_IURI="//input[@name='%s']/@value"
PIE_MAGICK='"pie" value="'
ETM_MAGICK='"etm" value="'
TOKEN_MAGICK='"skypetoken" value="'

sc={
		"sess":requests.session(),
		"lock":threading.Lock(),
		"reqs":{},
		"cook":{},
		"hmsg":SWC_HMDV,
		"tarq":0
		}

def sc_lock():
	ret=sc["lock"].acquire(True)
	assert ret==True

def sc_unlock():
	ret=sc["lock"].release()

def std_headers(url):
	global sc
	host=requests.utils.urlparse(url).netloc
	ret={
			"Host":host,
			"Accept-Encodings":"gzip",
			"Connection":"close"
			}
	#"BehaviorOverride":"redirectAs404",
	if ( host==SWC_HCON or host==SWC_HVID or host==SWC_HCNV ):
		h={
				"X-Skypetoken":sc["st"],
				"X-Stratus-Caller":SWC_NAME,
				"X-Stratus-Request":"abcd1234",
				"Origin":"https://web.skype.com/",
				"Referer":"https://web.skype.com/main",
				"Accept":"application/json; ver=1.0;",
				}
	elif ( host==sc["hmsg"] ):
		h={
			"RegistrationToken":sc["rtok"],
			"Referer":"https://web.skype.com/main",
			"Accept":"application/json; ver=1.0;",
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			}
	else:
		h={
				"Accept":"*/*"
				}
	ret.update(h)
	return ret

def req_async(rq,cb,n):
	global sc
	s=sc["sess"]
	r=s.send(rq)
	sc_lock()
	sc["cook"].update(r.cookies)
	sc_unlock()
	if cb is not None:
		cb(r)
	sc_lock()
	sc["reqs"].pop(n,"")
	sc_unlock()

def req(method,url,params=None,json=None,headers=None,data=None,cookies=None,cb=None):
	global sc
	s=sc["sess"]
	h=headers
	if h is None:
			h=std_headers(url)
	r=requests.Request(method,url,headers=h,params=params,json=json,data=data,cookies=sc["cook"])
	pr=s.prepare_request(r)
	n="[⌚%f]%s␣%s␣HTTP/1.0"%(time.time(),method.upper(),url),
	t=threading.Thread(group=None,target=req_async,name=n,args=(pr,cb,n))
	sc_lock()
	sc["reqs"].update({n:t})
	sc_unlock()
	t.start()

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
	req('post','https://'+sc["hmsg"]+"/v1/users/ME/endpoints/"+sc["epid"]+"/subscriptions",json=p,cb=dothings)

def getid_cb(r):
	global sc
	sc_lock()
	j=r.json()
	sc["unam"]=j["username"]
	if("displayname" in j):
		sc["nick"]=j["displayname"]
	else:
		if("firstname" in j):
			sc["nick"]=j["firstname"]
		else:
			sc["nick"]=j["username"]
	sc_unlock()

def getid():
	global sc
	req('get','https://'+SWC_HCON+'/users/self/displayname',json={},cb=getid_cb)

def subuser(u):
	global sc
	p={
			"contacts":{
				"id":"8:"+u
				}
			}
	req('get','https://'+sc["hmsg"]+'/users/ME/contacts',json={})

def authrq_cb(r):
	j=r.json()
	lt=sc["tarq"]
	for r in j:
		et=r["event_time"].split('.')
		ets=time.mktime(time.strptime(et[0],"%Y-%m-%d %H:%M:%S"))
		et=ets+float("0."+et[1])
		sn=r["sender"]
		gr=r["greeting"]
		if (int(et)<=int(sc["tarq"])):
			continue
		req('put','https://'+SWC_HCON+'/users/self/contacts/auth-request/'+sn+"/accept",json={})
		subuser(sn)
		lt=max(lt,et)
	sc_lock()
	sc["tarq"]=lt
	sc["fnord"]=r
	sc_unlock()

def authrq():
	global sc
	req('get','https://'+SWC_HCON+'/users/self/contacts/auth-request',cb=authrq_cb)

def blist_cb(r):
	j=r.json()
	for r in j:
		sn=r["skypename"]
		subuser(sn)

def blist():
	global sc
	req('get','https://'+SWC_HCON+'/users/self/contacts',json={},cb=blist_cb)

def token_cb(r):
	if("location" in r.headers):
		hnew=requests.utils.urlparse(r.headers["location"]).netloc
		if (sc["hmsg"]!=hnew):
			sc_lock()
			sc["hmsg"]=hnew
			sc_unlock()
			token()
			return
	rth=r.headers["Set-RegistrationToken"]
	rtl=requests.utils.parse_header_links(rth)[0]
	sc_lock()
	sc["rtok"]=rtl["url"]
	sc["rexp"]=rtl["expires"]
	sc["epid"]=rtl["endpointId"]
	sc_unlock()
	subscribe()

def token():
	global sc
	ct=str(int(time.time()))
	sc.pop("rtok","")
	sc.pop("epid","")
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
	req('post',"https://"+sc["hmsg"]+"/v1/users/ME/endpoints",json={},headers=h,cb=token_cb)


def link():
	print("link...")
	global sc
	url="https://%s/v1/users/ME/endpoints/%s/presenceDocs/messagingService"%(sc["hmsg"],requests.utils.quote(sc["epid"],safe=""))
	p={
			"id":"messagingService",
			"type":"EndpointPresenceDoc",
			"selfLink":"uri",
			"privateInfo":{
				"epname":"skype"
				},
			"publicInfo":{
				"capabilities":"",
				"type":1,
				"typ":1,
				"skypeNameVersion":SWC_VERS+"/"+SWC_NAME,
				"nodeInfo":"xx",
				"version":SWC_VERS
				}
			}
	s={
			"status":"Online"
			}
	req('put',"https://"+sc["hmsg"]+"/v1/users/ME/presenceDocs/messagingService",json=s)
	req('put',url,json=p)

def poll_cb(r):
	if(r.text==""):
		if (int(time.time())>int(sc["rexp"])):
			token()
		return
	j=r.json()
	if("errorCode" in j):
		if(j["errorCode"]==729):
			token()
			return
	if("eventMessages" in j):
		for r in j["eventMessages"]:
			res=r["resource"]
			if(r["resourceType"]=="NewMessage"):
				mt=res["messagetype"]
				if(mt=="Text" or mt=="RichText"):
					print("%s|%s> %s"%(res["originalarrivaltime"],res["imdisplayname"],res["content"]),end='')
	poll()

def poll():
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Connection":"close",
			"Accept":"application/json; ver=1.0;",
			"BehaviorOverride":"redirectAs404",
			"Origin":"https://web.skype.com/",
			"Referer":"https://web.skype.com/main",
			"RegistrationToken":sc["rtok"],
			"Content-Type":"application/json",
			"Accept-Encodings":"gzip",
			"Host":sc["hmsg"]
			}
	req('post','https://'+sc["hmsg"]+"/v1/users/ME/endpoints/"+sc["epid"]+"/subscriptions/0/poll",json={},cb=poll_cb)


def dothings(r=None):
	global sc
	if ("rtok" in sc):
		getid()
		authrq()
		blist()
		poll()
		link()
	else:
		token()

def login(username,password):
	global sc
	h={
			"ClientInfo":"os=Windows; osVer=8.1; proc=Win32; lcid=en-us; deviceType=1; country=n/a; clientName=" + SWC_NAME + "; clientVer=" + SWC_VERS,
			"Content-Type":"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
			"Connection":"close",
			"Accept":"*/*",
			"BehaviorOverride":"redirectAs404",
			"Host":SWC_HLOG,
			}
	p={
			"method":"skype",
			"client_id":SWC_CMAG,
			"redirect_uri":"https://web.skype.com"
			}
	r=requests.get('https://'+SWC_HLOG+'/login',params=p)
	if("location" in r.headers):
		print("Redirecting to "+r.headers["location"])
		r=requests.get(r.headers["location"],params=p)
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
	zm=int(z/60)
	zh=int(zm/60)
	zm-=zh*60
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
	d={
			"client_id":SWC_CMAG,
			"redirect_uri":"https://web.skype.com/"
			}
	r=requests.post("https://"+SWC_HLOG+"/login",params=d,data=p,headers=h)
	if("location" in r.headers):
		print("Redirecting to "+r.headers["location"])
		r=requests.post(r.headers["Location"],params=d,data=p,headers=h)
	sc["cook"]=r.cookies
	assert r.status_code==200
	t=html.fromstring(r.text)
	st=t.xpath(SWC_IURI%SWC_ITOK)
	if (len(st)>0):
		sc["st"]=st[0]
	else:
		#unhandled captcha
		return "CAPTCHA!"
	dothings()
	return "OK~"


print(login("rtmfaerie","OppaiDolly"))
while 1:
	if (len(sc["reqs"])==0):
		poll()
	time.sleep(1)
