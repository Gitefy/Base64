#!/usr/bin/env python3
import base64, copy, concurrent.futures, gzip, json, math, os, re, shutil, subprocess, time
import urllib.parse, urllib.request
from pathlib import Path
import yaml

OUT = Path("US_SG_JP_subscription_base64.txt")
STATS = Path("US_SG_JP_stats.json")
QZZ64 = ["https://234.qzz.io/fsllist64", "https://isdo.dpdns.org/fsllist64"]
QZZYAML = ["https://234.qzz.io/fsllistyaml", "https://isdo.dpdns.org/fsllistyaml"]
TEST_URL = "https://www.gstatic.com/generate_204"
SCHEMES = ("vmess://","vless://","trojan://","ss://","ssr://","hysteria2://","hy2://","tuic://","socks://","http://","https://")

def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 GitHub-Actions Subscription-Refresh"})
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
    if "🇺🇸" in s or "美国" in s or "美國" in s or "UNITED STATES" in u or "USA" in u or re.search(r"(^|[^A-Z0-9])US([^A-Z0-9]|$)", u):
        return "US"
    if "🇸🇬" in s or "新加坡" in s or "狮城" in s or "獅城" in s or "SINGAPORE" in u or re.search(r"(^|[^A-Z0-9])SG([^A-Z0-9]|$)", u):
        return "SG"
    if "🇯🇵" in s or "日本" in s or "JAPAN" in u or re.search(r"(^|[^A-Z0-9])JP([^A-Z0-9]|$)", u):
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
            http_get("http://127.0.0.1:9090/version",2); return True
        except Exception: time.sleep(.2)
    return False

def delay_one(c):
    name=urllib.parse.quote(c["test_name"],safe="")
    test=urllib.parse.quote(TEST_URL,safe="")
    for timeout in (5500,8000):
        url=f"http://127.0.0.1:9090/proxies/{name}/delay?timeout={timeout}&url={test}"
        try:
            data=json.loads(http_get(url,timeout/1000+3).decode())
            d=int(data.get("delay",0) or 0)
            if d>0: return d
        except Exception:
            pass
    return None

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
    srcy,rawy=fetch_first(QZZYAML)
    y=yaml.safe_load(rawy.decode("utf-8","ignore"))
    proxies=(y or {}).get("proxies",[]) if isinstance(y,dict) else []
    if not proxies: raise RuntimeError("Clash subscription contains no proxies")
    indexes=proxy_indexes(proxies)

    parsed=[]
    for u in old_lines:
        x=parse_uri(u,"github")
        if x: parsed.append(x)
    for u in new_lines:
        x=parse_uri(u,"qzz")
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
        if p is None and c["scheme"]=="vmess":
            p=vmess_to_clash(c)
        if p is None: continue
        p["name"]=c["test_name"]
        c["proxy"]=p
        testable.append(c)
    if not testable: raise RuntimeError("no testable candidates")

    cfg={"mixed-port":7890,"allow-lan":False,"mode":"global","log-level":"silent",
         "external-controller":"127.0.0.1:9090",
         "proxies":[c["proxy"] for c in testable],
         "proxy-groups":[{"name":"TEST","type":"select","proxies":[c["test_name"] for c in testable]}],
         "rules":["MATCH,TEST"]}
    Path("test_config.yaml").write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding="utf-8")
    download_mihomo()
    proc=subprocess.Popen(["./mihomo","-f","test_config.yaml"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        if not controller_ready(): raise RuntimeError("mihomo controller did not start")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            fut={ex.submit(delay_one,c):c for c in testable}
            for f in concurrent.futures.as_completed(fut):
                c=fut[f]; c["delay"]=f.result()
    finally:
        proc.terminate()
        try: proc.wait(5)
        except: proc.kill()

    usable=[c for c in testable if c.get("delay")]
    usable.sort(key=lambda x:x["delay"])
    counts={k:sum(1 for x in usable if x["country"]==k) for k in ("US","SG","JP")}
    if len(usable)>200:
        q=quotas(counts,100)
        selected=[]
        for country in ("US","SG","JP"):
            arr=[x for x in usable if x["country"]==country]
            selected += arr[:q[country]]
        selected.sort(key=lambda x:x["delay"])
    else:
        q=counts.copy()
        selected=usable

    if not selected: raise RuntimeError("URL test found zero usable nodes")
    plain="\n".join(c["uri"] for c in selected)+"\n"
    OUT.write_text(base64.b64encode(plain.encode()).decode()+"\n",encoding="utf-8")
    stats={
        "source_v2ray":src64,"source_clash":srcy,
        "previous_github_nodes":len(old_lines),"source_nodes":len(new_lines),
        "filtered_unique":len(candidates),"testable":len(testable),"usable":len(usable),"selected":len(selected),
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

# trigger refresh workflow
