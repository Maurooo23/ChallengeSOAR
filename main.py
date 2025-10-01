import json
import yaml
from datetime import datetime
import argparse
import uuid
from jinja2 import Template
from pathlib import Path

#funciones para poder obtener los archivos del challenge
def load_json(obj):
    return json.load(open(obj))

def load_yaml(yml):
    return json.load(open(yml))

#funcion para poder normar la data.
def mapeo(alerta):
    #alert = json.loads(alerta.read_text(encoding="utf-8"))
    indicators = []
    lista_iocs = alerta.get("indicators", [])
    #normalizamos iocs
    for ip in lista_iocs.get("ipv4",[]):
        indicators.append({"type":"ip", "value":ip})
    for domain in lista_iocs.get("domains", []):
        indicators.append({"type":"domain", "value": domain})
    for urls in lista_iocs.get("urls", []):
        indicators.append({"type":"url", "value": urls})
    for sha in lista_iocs.get("sha256", []):
        indicators.append({"type": "sha256", "value": sha})

    return{
        "incident_id": str(uuid.uuid4()),
        "source_alert": alerta,
        "asset": alerta.get("asset", {}),
        "indicators": indicators,
        "triage": {},
        "mitre": "",
        "actions": "",
        "timeline": [{
            "stage": "ingesta",
            "date": datetime.utcnow().isoformat(),
            "details": "Alerta mapeada e incidente creado con exito."
        }]
    }


#creamos una funcion para poder hacer enrichment
#estamos recorriendo todos los .json de provider para detectar match ioc y provider
def enrichment_alerta(incidente, providerPath):
    for iocs in incidente["indicators"]:
        #ioc = ipv4, domain, etc.
        #print(iocs)
        valor = iocs["value"]
        type = iocs["type"]
        #print(type)
        #valor = 1.2.3.4, bad....
        risk = {"verdict": "unknown", "score": 0, "sources": []}

        for file in Path(providerPath).glob("*.json"):
            data = json.loads(file.read_text(encoding="utf-8"))
            #print(data)
            #print(valor)
            ioc_key = None
            for key in ["domain", "ip", "sha256"]:
                if key in data:
                    ioc_key = key
                    break
            if ioc_key and data[ioc_key] == valor:
                risk["verdict"] = data.get("reputation") or data.get("classification") or data.get("risk") or "unknown"
                risk["score"] = data.get("score", 0) or data.get("confidence")
                risk["sources"].append(file.stem)

        iocs["risk"] = risk
    incidente["timeline"].append({
            "stage": "enrichment",
            "date": datetime.utcnow().isoformat(),
            "details": f"Enriquecidos {len(incidente['indicators'])} indicadores"
        })    
    return incidente

#creamos una funcion para aplicar tecnicas, tag, triage.
def triage_alerta(incidente, allowlists, mitre):
    #seteamnos severidades segun documento
    mapeo_severidad = {
        "Malware": 70,
        "Phishing": 60,
        "Beaconing":65,
        "CredentialAccess": 75,
        "C2": 80
    }
    sev = mapeo_severidad.get(incidente.get("type"), 40)

    #intel booosts
    flag = 0
    for ioc in incidente["indicators"]:
        verdict = ioc.get("risk", {}).get("verdict", "unknown")
        if verdict == "malicious":
            sev += 20
            flag += 1
        elif verdict == "suspicious":
            sev +=10
            flag +=1
    if flag > 1:
        sev += min((flag -1)*5, 20)
    
    #lista permitidos
    allowlist = yaml.safe_load(open(allowlists, "r"))
    count = 0
    for ioc in incidente["indicators"]:
        if ioc["value"] in allowlist.get("indicators", []):
            ioc["allowlisted"] = True
            sev -= 25
            incidente.setdefault("triage", {}).setdefault("tags", []).append("allowlisted")
            count +=1
        else:
            ioc["allowlisted"] = False
    
    #en caso que esten todo allow - supres
    if count == len(incidente["indicators"]) and count > 0:
        sev = 0
        suppressed = True
        tags = ["suppressed"]
    else:
        suppressed = False
        tags = incidente.get("triage", {}).get("tags", [])

    #campl y buckt
    sev = max(0, min(sev, 100))
    if sev == 0:
        bucket = "suppressed"
    elif sev <= 39:
        bucket = "Low"
    elif sev <= 69:
        bucket = "Medium"
    elif sev <=88:
        bucket = "High"
    else:
        bucket = "Critical"
    
    #Tag mitre
    mte = yaml.safe_load(open(mitre, "r"))
    mitre_mapeo = mte.get("types", {})
    tecnicas = mitre_mapeo.get(incidente["source_alert"]["type"], ["T1040"])

    incidente["triage"] = {
        "severity": sev,
        "bucket": bucket,
        "tags": tags,
        "suppressed": suppressed
    }
    incidente["mitre"] = {"tecnicas": tecnicas}

    incidente["timeline"].append({
            "stage": "triage",
            "date": datetime.utcnow().isoformat(),
            "details": f"Severidad {incidente['triage']['bucket']} ({incidente['triage']['severity']})"
        })

    return incidente

#outputs
    #isolation
def isolation(incidente):
    actions = []
    severidad = incidente["triage"]["severity"]
    device_id = incidente["asset"]["device_id"]

    #if final severity ≥ 70 and asset.device_id present and not allowlisted:
    #Append a line to out/isolation.log:
    if severidad >= 70 and device_id and not incidente["triage"].get("suppressed", False):
        today = datetime.utcnow().isoformat()
        action = {
            "type":"isolate",
            "target":f"device:{device_id}",
            "result":"isolated",
            "ts":today
        }
        actions.append(action)

        #ecribimos log
        out_dir = Path("out")
        out_dir.mkdir(exist_ok=True)
        log_file = out_dir / "isolation.log"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"{today} isolate device_id{device_id} incident={incidente["incident_id"]} result=isolated\n")

    incidente["actions"] = actions
    if actions:
        incidente["timeline"].append({
            "stage": "response",
            "ts": datetime.utcnow().isoformat(),
            "details": f"{len(actions)} accion(es) ejecutadas: {[a['type'] for a in actions]}"
        })
    else:
        incidente["timeline"].append({
            "stage": "response",
            "ts": datetime.utcnow().isoformat(),
            "details": "No se ejecutaron acciones"
        })
        return incidente    

#guardamos json
def guardar_incidente(incidente):
    ruta = Path("out/incidents")
    ruta.mkdir(parents=True, exist_ok=True)
    path = ruta / f"{incidente["incident_id"]}.json"

    with path.open("w", encoding="utf-8") as f:
        json.dump(incidente, f, indent=2)
    
    print(f"[+] Incidente guardado en: {path}")

#jinja 2 template
def template_jinja(incidente):
    ruta = Path("out/summaries")
    ruta.mkdir(parents=True, exist_ok=True)
    path = ruta / f"{incidente["incident_id"]}.md"

    template_jinja = """ 
# Incident Report: {{ incidente.incident_id }}

**Severity:** {{ incidente.triage.bucket }} ({{ incidente.triage.severity }})
**Tags:** {{ incidente.triage.tags | join(", ") if incidente.triage.tags else "None" }}

## Indicators
| Type | Value | Verdict | Score |
|------|-------|---------|-------|
{% for ind in incidente.indicators %}
| {{ ind.type }} | {{ ind.value }} | {{ ind.risk.verdict }} | {{ ind.risk.score }} |
{% endfor %}

## MITRE ATT&CK
Techniques: {{ incidente.mitre.techniques | join(", ") }}

## Actions
{% if incidente.actions %}
{% for act in incidente.actions %}
- {{ act.ts }} → {{ act.type }} {{ act.target }} → **{{ act.result }}**
{% endfor %}
{% else %}
_No actions taken_
{% endif %}
"""
    template = Template(template_jinja)
    summary = template.render(incidente=incidente)

    with path.open("w", encoding="utf-8") as f:
        f.write(summary)
    
    print(f"[+] Summary guardado en: {path}")


#main()
argParse= argparse.ArgumentParser(); argParse.add_argument("alerta"); args = argParse.parse_args()
alerta = load_json(args.alerta)
providerPath="mocks/it"
allowlist="configs/allowlists.yml"
mitre="configs/mitre_map.yml"
incidente=mapeo(alerta)
#print(incidente)
enrich=enrichment_alerta(incidente, providerPath)
#print(enrich)
triage = triage_alerta(enrich, allowlist, mitre)
#print(triage)
isolated = isolation(triage)
#print(isolated)
respons = guardar_incidente(triage)
print(respons)
summary = template_jinja(triage)
#incidente=enrichment_alerta(incidente, providerPath)



