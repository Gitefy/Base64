#!/usr/bin/env python3
import base64, copy, concurrent.futures, gzip, json, math, os, re, shutil, subprocess, time
import urllib.parse, urllib.request
from pathlib import Path
import yaml

OUT = Path("US_SG_JP_subscription_base64.txt")
STATS = Path("US_SG_JP_stats.json")
QZZ64 = ["https://234.qzz.io/fsllist64", "https://isdo.dpdns.org/fsllist64"]
QZZYAML = ["https://234.qzz.io/fsllistyaml", "https://isdo.dpdns.org/fsllistyaml"]
JIKUN_URL = "https://jikun.zmxoo.xyz/subapi?token=free_13V4wWlMnOxPCGn&placeholder=1&placeholder=2&placeholder=3"
JIJI_URL = "https://b.545437.xyz/jiji?token=05c7f843a5cc4c57383fb5085a57aa33"
MITCE_URL = "https://app.mitce.net/?sid=532469&token=fec41d1627b2a7ae5207"
MANUAL_SEEDS = [
    "vless://e2632874-614e-4261-af62-52aca3358e4e@173.234.14.105:59615?encryption=none&flow=xtls-rprx-vision&security=reality&sni=biosmod.partners.nvidia.com&fp=chrome&pbk=7PB-58vYXFLNhK6kY8bJJO3-fPOXTPQJ0UqDlhSOH3M&sid=6b&spx=%2F7200b0b923f69f9&type=tcp&headerType=none#Singapore-vpn"
]
TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]
STRICT_TEST_ROUNDS = 3
REQUIRED_SUCCESS_ROUNDS = 2
MAX_DELAY_MS = 3000
TEST_TIMEOUT_MS = 5000
PROBE_BINARY = Path("/opt/china-probe/mihomo")
PROBE_BASE_CONFIG = Path("/opt/china-probe/config.yaml")
PROBE_ROUTING_MARK = 524288
PROBE_MIXED_PORT = 17891
PROBE_CONTROLLER_PORT = 19091
SCHEMES = ("vmess://","vless://","trojan://","ss://","ssr://","hysteria2://","hy2://","tuic://","socks://","http://","https://")

def http_get(url, timeout=25, user_agent="Mozilla/5.0 GitHub-Actions Subscription-Refresh"):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def fetch_first(urls):
    errs=[]
    for u in urls:
        try:
            b=http_get(u)
            if b:
                print("fetched", u, len(b))
                return u,b
        except Exception as e:
            errs.append(f"{u}: {e}")
    raise RuntimeError("all fetches failed: " + " | ".join(errs))

def b64decode_loose(s):
    s="".join(s.split())
    return base64.b64decode(s + "="*((4-len(s)%4)%4))

def subscription_lines(raw):
    text=raw.decode("utf-8","ignore").strip()
    lines=[x.strip() for x in text.splitlines() if x.strip()]
    if any(x.startswith(SCHEMES) for x in lines):
        return [x for x in lines if x.startswith(SCHEMES)]
    try:
        dec=b64decode_loose(text).decode("utf-8","ignore")
        return [x.strip() for x in dec.splitlines() if x.strip().startswith(SCHEMES)]
    except Exception:
        return []

def country_from_name(name):
    s=urllib.parse.unquote(str(name or "")).strip()
    u=s.upper()
    # Classify only from the first display segment before "|" so capability
    # tags in later segments (for example TK-US / YT-US / SP-US) do not
    # misclassify a node. Providers often prepend symbols/emojis, so allow the
    # actual country token to appear anywhere inside that first segment.
    head_raw=s.split("|",1)[0].strip()
    head=head_raw.upper()

    if "🇺🇸" in head_raw: return "US"
    if "🇸🇬" in head_raw: return "SG"
    if "🇯🇵" in head_raw: return "JP"

    if re.search(r"(?:^|[^A-Z0-9])(US|USA|SEATTLE|LOS ANGELES|SAN JOSE|DALLAS|NEW YORK|CHICAGO|MIAMI)(?:[^A-Z0-9]|$)", head):
        return "US"
    if re.search(r"(?:^|[^A-Z0-9])(SG|SINGAPORE)(?:[^A-Z0-9]|$)", head):
        return "SG"
    if re.search(r"(?:^|[^A-Z0-9])(JP|JAPAN|TOKYO|OSAKA)(?:[^A-Z0-9]|$)", head):
        return "JP"

    if re.search(r"(美国|洛杉矶|西雅图|圣何塞|达拉斯|纽约|芝加哥|迈阿密)", head_raw):
        return "US"
    if re.search(r"(新加坡|狮城)", head_raw):
        return "SG"
    if re.search(r"(日本|东京|大阪)", head_raw):
        return "JP"
    return None

def parse_ss_hostport(uri):
    try:
        p=urllib.parse.urlsplit(uri)
        if p.hostname:
            return p.hostname, p.port
        body=uri.split("://",1)[1].split("#",1)[0].split("?",1)[0]
        if "@" not in body:
            body=b64decode_loose(body).decode("utf-8","ignore")
        hp=body.rsplit("@",1)[-1]
        if hp.startswith("["):
            host,port=hp.rsplit("]:",1); return host[1:], int(port)
        host,port=hp.rsplit(":",1); return host, int(port)
    except Exception:
        return None,None

def parse_uri(uri, source):
    uri=uri.strip()
    if uri.startswith("vmess://"):
        try:
            obj=json.loads(b64decode_loose(uri[8:]).decode("utf-8","ignore"))
            name=str(obj.get("ps",""))
            c=country_from_name(name)
            if not c: return None
            server=str(obj.get("add","")).strip()
            port=int(str(obj.get("port","0")))
            canon={k:obj[k] for k in sorted(obj) if k!="ps"}
            key="vmess:"+json.dumps(canon,sort_keys=True,separators=(",",":"),ensure_ascii=False)
            return {"uri":uri,"scheme":"vmess","name":name,"country":c,"server":server,"port":port,"key":key,"vmess":obj,"source":source}
        except Exception:
            return None
    try:
        p=urllib.parse.urlsplit(uri)
        scheme=p.scheme.lower()
        name=urllib.parse.unquote(p.fragment or "")
        c=country_from_name(name)
        if not c: return None
        server,port=p.hostname,p.port
        if scheme=="ss" and not server:
            server,port=parse_ss_hostport(uri)
        q=urllib.parse.parse_qsl(p.query,keep_blank_values=True)
        q.sort()
        netloc=p.netloc
        canon=urllib.parse.urlunsplit((scheme,netloc,p.path,urllib.parse.urlencode(q,doseq=True),""))
        return {"uri":uri,"scheme":scheme,"name":name,"country":c,"server":str(server or ""),"port":int(port or 0),"key":canon,"source":source}
    except Exception:
        return None

def vmess_to_clash(c):
    o=c.get("vmess") or {}
    try:
        p={"name":c["test_name"],"type":"vmess","server":o["add"],"port":int(o["port"]),"uuid":o["id"],
           "alterId":int(o.get("aid",0) or 0),"cipher":o.get("scy") or "auto","udp":True}
        net=(o.get("net") or "tcp").lower()
        if net in ("ws","grpc","h2","http","tcp"):
            p["network"]="tcp" if net=="http" else net
        tls=str(o.get("tls","")).lower()
        if tls and tls not in ("none","false","0"):
            p["tls"]=True
            if o.get("sni"): p["servername"]=o["sni"]
            p["skip-cert-verify"]=True
        if net=="ws":
            opts={}
            if o.get("path"): opts["path"]=o["path"]
            if o.get("host"): opts["headers"]={"Host":o["host"]}
            if opts: p["ws-opts"]=opts
        elif net=="grpc":
            if o.get("path"): p["grpc-opts"]={"grpc-service-name":str(o["path"]).lstrip("/")}
        elif net in ("h2","http"):
            opts={}
            if o.get("path"): opts["path"]=o["path"]
            if o.get("host"): opts["host"]=[o["host"]]
            if opts: p["h2-opts"]=opts
        return p
    except Exception:
        return None

def _q1(q, key, default=""):
    v=q.get(key)
    return v[0] if v else default

def uri_to_clash(c):
    uri=c.get("uri","")
    try:
        p=urllib.parse.urlsplit(uri)
        scheme=p.scheme.lower()
        q=urllib.parse.parse_qs(p.query,keep_blank_values=True)
        if scheme=="ss":
            user=urllib.parse.unquote(p.username or "")
            try:
                decoded=b64decode_loose(user).decode("utf-8","ignore")
            except Exception:
                decoded=user
            if ":" not in decoded: return None
            cipher,password=decoded.split(":",1)
            return {"name":c["test_name"],"type":"ss","server":p.hostname,"port":p.port,
                    "cipher":cipher,"password":password,"udp":True}

        if scheme in ("hysteria2","hy2"):
            auth=urllib.parse.unquote(p.username or "")
            if p.password is not None:
                auth += ":" + urllib.parse.unquote(p.password)
            x={"name":c["test_name"],"type":"hysteria2","server":p.hostname,"port":p.port,
               "password":auth,"udp":True}
            sni=_q1(q,"sni") or _q1(q,"peer")
            if sni: x["sni"]=sni
            if _q1(q,"insecure") in ("1","true","True") or _q1(q,"allowInsecure") in ("1","true","True"):
                x["skip-cert-verify"]=True
            obfs=_q1(q,"obfs")
            if obfs:
                x["obfs"]=obfs
                op=_q1(q,"obfs-password")
                if op: x["obfs-password"]=op
            return x

        if scheme=="vless":
            x={"name":c["test_name"],"type":"vless","server":p.hostname,"port":p.port,
               "uuid":urllib.parse.unquote(p.username or ""),"udp":True}
            sec=(_q1(q,"security") or "none").lower()
            net=(_q1(q,"type") or "tcp").lower()
            if net in ("ws","grpc","tcp","h2"):
                x["network"]=net
            if sec in ("tls","reality"):
                x["tls"]=True
                sni=_q1(q,"sni")
                if sni: x["servername"]=sni
                if _q1(q,"allowInsecure") in ("1","true","True") or _q1(q,"insecure") in ("1","true","True"):
                    x["skip-cert-verify"]=True
            fp=_q1(q,"fp")
            if fp: x["client-fingerprint"]=fp
            flow=_q1(q,"flow")
            if flow: x["flow"]=flow
            pe=_q1(q,"packetEncoding")
            if pe: x["packet-encoding"]=pe
            if sec=="reality":
                ro={}
                if _q1(q,"pbk"): ro["public-key"]=_q1(q,"pbk")
                if _q1(q,"sid"): ro["short-id"]=_q1(q,"sid")
                if ro: x["reality-opts"]=ro
            if net=="ws":
                wo={}
                if _q1(q,"path"): wo["path"]=_q1(q,"path")
                if _q1(q,"host"): wo["headers"]={"Host":_q1(q,"host")}
                if wo: x["ws-opts"]=wo
            elif net=="grpc":
                svc=_q1(q,"serviceName") or _q1(q,"path")
                if svc: x["grpc-opts"]={"grpc-service-name":svc.lstrip("/")}
            return x
    except Exception:
        return None
    return None

def proxy_indexes(proxies):
    by_exact={}; by_sp={}; by_spt={}; by_name={}
    for p in proxies:
        if not isinstance(p,dict): continue
        n=str(p.get("name","")); s=str(p.get("server","")).lower()
        try: port=int(p.get("port",0))
        except: port=0
        t=str(p.get("type","")).lower()
        by_exact.setdefault((n,s,port),[]).append(p)
        by_sp.setdefault((s,port),[]).append(p)
        by_spt.setdefault((s,port,t),[]).append(p)
        by_name.setdefault(n,[]).append(p)
    return by_exact,by_sp,by_spt,by_name

def find_proxy(c, indexes):
    by_exact,by_sp,by_spt,by_name=indexes
    s=str(c.get("server","")).lower(); port=int(c.get("port",0) or 0); n=c.get("name","")
    x=by_exact.get((n,s,port),[])
    if x: return copy.deepcopy(x[0])
    typ={"hy2":"hysteria2"}.get(c["scheme"],c["scheme"])
    x=by_spt.get((s,port,typ),[])
    if len(x)==1: return copy.deepcopy(x[0])
    x=by_sp.get((s,port),[])
    if len(x)==1: return copy.deepcopy(x[0])
    x=by_name.get(n,[])
    if len(x)==1: return copy.deepcopy(x[0])
    return None

def download_mihomo():
    api=json.loads(http_get("https://api.github.com/repos/MetaCubeX/mihomo/releases/latest").decode())
    assets=[a for a in api.get("assets",[]) if "linux-amd64" in a.get("name","") and a.get("name","").endswith(".gz")]
    if not assets: raise RuntimeError("no linux-amd64 mihomo asset")
    def score(a):
        n=a["name"]
        return (0 if "compatible" in n else 1 if re.search(r"mihomo-linux-amd64-v\d",n) else 2, len(n))
    a=sorted(assets,key=score)[0]
    print("mihomo asset",a["name"])
    gz=http_get(a["browser_download_url"],60)
    Path("mihomo.gz").write_bytes(gz)
    with gzip.open("mihomo.gz","rb") as f, open("mihomo","wb") as o: shutil.copyfileobj(f,o)
    os.chmod("mihomo",0o755)

def controller_ready():
    for _ in range(50):
        try:
            http_get(f"http://127.0.0.1:{PROBE_CONTROLLER_PORT}/version",2); return True
        except Exception: time.sleep(.2)
    return False

def delay_one(c):
    name=urllib.parse.quote(c["test_name"],safe="")
    successful_rounds=[]
    c["round_results"]=[]
    last_round_ok=False

    for round_no in range(STRICT_TEST_ROUNDS):
        round_delays=[]
        round_ok=True
        for test_url in TEST_URLS:
            test=urllib.parse.quote(test_url,safe="")
            url=f"http://127.0.0.1:{PROBE_CONTROLLER_PORT}/proxies/{name}/delay?timeout={TEST_TIMEOUT_MS}&url={test}"
            try:
                data=json.loads(http_get(url,TEST_TIMEOUT_MS/1000+2).decode())
                d=int(data.get("delay",0) or 0)
            except Exception:
                round_ok=False
                break
            if d <= 0 or d > MAX_DELAY_MS:
                round_ok=False
                break
            round_delays.append(d)

        last_round_ok=round_ok
        if round_ok:
            avg=round(sum(round_delays)/len(round_delays))
            successful_rounds.append(avg)
            c["round_results"].append(avg)
        else:
            c["round_results"].append(None)

        if round_no + 1 < STRICT_TEST_ROUNDS:
            time.sleep(0.4)

    if len(successful_rounds) < REQUIRED_SUCCESS_ROUNDS or not last_round_ok:
        return None
    return round(sum(successful_rounds)/len(successful_rounds))

def quotas(counts,total_keep):
    total=sum(counts.values())
    if total<=total_keep: return counts.copy()
    raw={c:counts[c]*total_keep/total for c in counts}
    q={c:min(counts[c],int(math.floor(raw[c]))) for c in counts}
    for c in counts:
        if counts[c]>0 and q[c]==0: q[c]=1
    while sum(q.values())>total_keep:
        c=max((x for x in q if q[x]>1), key=lambda x:(q[x]-raw[x],q[x]), default=None)
        if c is None: break
        q[c]-=1
    while sum(q.values())<total_keep:
        choices=[c for c in q if q[c]<counts[c]]
        if not choices: break
        c=max(choices,key=lambda x:(raw[x]-q[x],counts[x]-q[x]))
        q[c]+=1
    return q

def main():
    old_lines=[]
    if OUT.exists():
        try: old_lines=subscription_lines(OUT.read_bytes())
        except Exception: pass
    src64,raw64=fetch_first(QZZ64)
    new_lines=subscription_lines(raw64)
    if not new_lines: raise RuntimeError("V2Ray subscription decoded to zero share links")

    jikun_lines=[]
    try:
        rawj=http_get(JIKUN_URL, 30, "v2rayN")
        jikun_lines=subscription_lines(rawj)
        print("fetched jikun generic", len(rawj), "bytes", len(jikun_lines), "share links")
    except Exception as e:
        print("jikun generic fetch failed:", e)

    jiji_lines=[]
    if JIJI_URL:
        try:
            rawjj=http_get(JIJI_URL, 30, "v2rayN")
            jiji_lines=subscription_lines(rawjj)
            print("fetched jiji generic", len(rawjj), "bytes", len(jiji_lines), "share links")
        except Exception as e:
            print("jiji generic fetch failed:", e)

    mitce_lines=[]
    if MITCE_URL:
        try:
            rawm=http_get(MITCE_URL, 30, "v2rayN")
            mitce_lines=subscription_lines(rawm)
            print("fetched mitce generic", len(rawm), "bytes", len(mitce_lines), "share links")
        except Exception as e:
            print("mitce generic fetch failed:", e)

    srcy,rawy=fetch_first(QZZYAML)
    y=yaml.safe_load(rawy.decode("utf-8","ignore"))
    proxies=(y or {}).get("proxies",[]) if isinstance(y,dict) else []
    if not proxies: raise RuntimeError("Clash subscription contains no proxies")

    jikun_proxies=[]
    try:
        rawjy=http_get(JIKUN_URL, 30, "Clash.Meta")
        jy=yaml.safe_load(rawjy.decode("utf-8","ignore"))
        jikun_proxies=(jy or {}).get("proxies",[]) if isinstance(jy,dict) else []
        print("fetched jikun clash", len(rawjy), "bytes", len(jikun_proxies), "proxies")
    except Exception as e:
        print("jikun clash fetch failed:", e)

    jiji_proxies=[]
    if JIJI_URL:
        try:
            rawjjy=http_get(JIJI_URL, 30, "Clash.Meta")
            jjy=yaml.safe_load(rawjjy.decode("utf-8","ignore"))
            jiji_proxies=(jjy or {}).get("proxies",[]) if isinstance(jjy,dict) else []
            print("fetched jiji clash", len(rawjjy), "bytes", len(jiji_proxies), "proxies")
        except Exception as e:
            print("jiji clash fetch failed:", e)

    mitce_proxies=[]
    if MITCE_URL:
        try:
            rawmy=http_get(MITCE_URL, 30, "Clash.Meta")
            my=yaml.safe_load(rawmy.decode("utf-8","ignore"))
            mitce_proxies=(my or {}).get("proxies",[]) if isinstance(my,dict) else []
            print("fetched mitce clash", len(rawmy), "bytes", len(mitce_proxies), "proxies")
        except Exception as e:
            print("mitce clash fetch failed:", e)

    proxies = list(proxies) + list(jikun_proxies) + list(jiji_proxies) + list(mitce_proxies)
    indexes=proxy_indexes(proxies)

    parsed=[]
    for u in MANUAL_SEEDS:
        x=parse_uri(u,"manual")
        if x: parsed.append(x)
    for u in old_lines:
        x=parse_uri(u,"github")
        if x: parsed.append(x)
    for u in new_lines:
        x=parse_uri(u,"qzz")
        if x: parsed.append(x)
    for u in jikun_lines:
        x=parse_uri(u,"jikun")
        if x: parsed.append(x)
    for u in jiji_lines:
        x=parse_uri(u,"jiji")
        if x: parsed.append(x)

    for u in mitce_lines:
        x=parse_uri(u,"mitce")
        if x: parsed.append(x)

    dedup={}
    for c in parsed:
        if c["key"] not in dedup or dedup[c["key"]]["source"]!="github":
            dedup[c["key"]]=c
    candidates=list(dedup.values())
    print("filtered unique candidates",len(candidates),{k:sum(1 for x in candidates if x["country"]==k) for k in ("US","SG","JP")})

    testable=[]
    for i,c in enumerate(candidates,1):
        c["test_name"]=f"T{i:04d}"
        p=find_proxy(c,indexes)
        if p is None:
            p=vmess_to_clash(c) if c["scheme"]=="vmess" else uri_to_clash(c)
        if p is None: continue
        p["name"]=c["test_name"]
        c["proxy"]=p
        testable.append(c)
    if not testable: raise RuntimeError("no testable candidates")

    if not PROBE_BINARY.exists():
        raise RuntimeError(f"China probe binary missing: {PROBE_BINARY}")
    if not PROBE_BASE_CONFIG.exists():
        raise RuntimeError(f"China probe base config missing: {PROBE_BASE_CONFIG}")

    route_check=subprocess.run(
        ["ip","route","get","1.1.1.1","mark","0x80000"],
        capture_output=True,text=True,timeout=5
    )
    route_text=(route_check.stdout or "") + (route_check.stderr or "")
    if route_check.returncode != 0 or "dev eth0" not in route_text:
        raise RuntimeError("China probe route gate failed: " + route_text.strip())
    print("china probe route gate:", route_text.strip())

    base_cfg=yaml.safe_load(PROBE_BASE_CONFIG.read_text(encoding="utf-8")) or {}
    if not isinstance(base_cfg,dict):
        raise RuntimeError("China probe base config is not a YAML mapping")
    cfg=copy.deepcopy(base_cfg)

    # Avoid colliding with the always-on baseline china-probe.service.
    for key in ("port","socks-port","redir-port","tproxy-port"):
        cfg.pop(key,None)
    cfg["mixed-port"]=PROBE_MIXED_PORT
    cfg["allow-lan"]=False
    cfg["mode"]="global"
    cfg["log-level"]="silent"
    cfg["external-controller"]=f"127.0.0.1:{PROBE_CONTROLLER_PORT}"
    cfg["secret"]=""
    cfg["routing-mark"]=PROBE_ROUTING_MARK
    cfg["tun"]={"enable":False}
    if isinstance(cfg.get("dns"),dict):
        # Keep the independently configured redir-host resolvers, but do not
        # bind a second DNS listener that could collide with the baseline service.
        cfg["dns"].pop("listen",None)
    cfg["proxies"]=[c["proxy"] for c in testable]
    cfg["proxy-groups"]=[{"name":"TEST","type":"select","proxies":[c["test_name"] for c in testable]}]
    cfg["rules"]=["MATCH,TEST"]

    cfg_path=Path("test_config_china.yaml")
    runtime_dir=Path(".china-probe-actions-runtime")
    runtime_dir.mkdir(exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding="utf-8")

    child_env=os.environ.copy()
    for key in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"):
        child_env.pop(key,None)

    log_path=Path("china_probe_test.log")
    log_fh=log_path.open("w",encoding="utf-8")
    proc=subprocess.Popen(
        [str(PROBE_BINARY),"-d",str(runtime_dir),"-f",str(cfg_path)],
        stdout=log_fh,stderr=subprocess.STDOUT,env=child_env
    )
    try:
        if not controller_ready():
            log_fh.flush()
            tail=""
            try:
                tail="\n".join(log_path.read_text(encoding="utf-8",errors="ignore").splitlines()[-40:])
            except Exception:
                pass
            raise RuntimeError("China probe controller did not start. Log tail:\n" + tail)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            fut={ex.submit(delay_one,c):c for c in testable}
            for f in concurrent.futures.as_completed(fut):
                c=fut[f]; c["delay"]=f.result()
    finally:
        proc.terminate()
        try: proc.wait(5)
        except: proc.kill()
        log_fh.close()

    usable=[c for c in testable if c.get("delay")]
    usable.sort(key=lambda x:x["delay"])

    # Collapse duplicate endpoints after strict testing. If multiple configs
    # share the same server:port, keep only the lowest-latency passing config.
    endpoint_best={}
    for c in usable:
        endpoint=(str(c.get("server","")).lower(), int(c.get("port",0) or 0))
        if endpoint not in endpoint_best:
            endpoint_best[endpoint]=c
    endpoint_duplicates_removed=len(usable)-len(endpoint_best)
    usable=list(endpoint_best.values())
    usable.sort(key=lambda x:x["delay"])

    counts={k:sum(1 for x in usable if x["country"]==k) for k in ("US","SG","JP")}
    if len(usable)>200:
        q=quotas(counts,100)
        selected=[]
        for country in ("US","SG","JP"):
            arr=[x for x in usable if x["country"]==country]
            # Prefer TCP/TLS/REALITY/WS-family configs over UDP-heavy protocols
            # when the pool is large enough to require capping.
            def preference(x):
                scheme=x.get("scheme","")
                udp_heavy=1 if scheme in ("hysteria2","hy2","tuic") else 0
                return (udp_heavy, x["delay"])
            arr.sort(key=preference)
            selected += arr[:q[country]]
        selected.sort(key=lambda x:x["delay"])
    else:
        q=counts.copy()
        selected=usable

    if not selected: raise RuntimeError("URL test found zero usable nodes")
    plain="\n".join(c["uri"] for c in selected)+"\n"
    OUT.write_text(base64.b64encode(plain.encode()).decode()+"\n",encoding="utf-8")
    stats={
        "source_v2ray":src64,"source_clash":srcy,"source_jikun":JIKUN_URL,
        "source_jiji_configured":bool(JIJI_URL),"source_mitce_configured":bool(MITCE_URL),
        "manual_seed_nodes":len(MANUAL_SEEDS),
        "previous_github_nodes":len(old_lines),"source_nodes":len(new_lines),"jikun_source_nodes":len(jikun_lines),
        "jikun_clash_proxies":len(jikun_proxies),"jiji_source_nodes":len(jiji_lines),"jiji_clash_proxies":len(jiji_proxies),
        "mitce_source_nodes":len(mitce_lines),"mitce_clash_proxies":len(mitce_proxies),
        "filtered_unique":len(candidates),"testable":len(testable),"usable":len(usable),"selected":len(selected),
        "test_location":"china-vps-self-hosted",
        "probe_binary":str(PROBE_BINARY),"probe_routing_mark":PROBE_ROUTING_MARK,
        "probe_route_interface":"eth0","probe_controller_port":PROBE_CONTROLLER_PORT,
        "test_urls":TEST_URLS,"strict_test_rounds":STRICT_TEST_ROUNDS,
        "required_success_rounds":REQUIRED_SUCCESS_ROUNDS,"max_delay_ms":MAX_DELAY_MS,
        "endpoint_duplicates_removed":endpoint_duplicates_removed,
        "usable_by_country":counts,"selected_by_country":{k:sum(1 for x in selected if x["country"]==k) for k in ("US","SG","JP")},
        "quota_if_capped":q,
        "selected_latency_ms":{"min":min(x["delay"] for x in selected),"max":max(x["delay"] for x in selected),
                               "median":sorted(x["delay"] for x in selected)[len(selected)//2]},
        "generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    }
    STATS.write_text(json.dumps(stats,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(stats,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()

