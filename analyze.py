"""Explainable CTI analysis for a user-supplied asset/CVE inventory."""
import argparse
import csv
import datetime as dt
import ipaddress
import json
from pathlib import Path
import re
import uuid

def number(value,low,high,name):
    result=float(value)
    if not low <= result <= high:
        raise ValueError(f'{name} must be between {low} and {high}')
    return result

def triage(asset,kev):
    """Asset rows assert an affected CVE; this function does not discover exposure."""
    if asset.get('internet_exposed') not in ('true','false'):
        raise ValueError('internet_exposed must be true or false')
    criticality_value=number(asset.get('criticality','1'),1,5,'criticality')
    if not criticality_value.is_integer():
        raise ValueError('criticality must be a whole number')
    criticality=int(criticality_value)
    cvss=number(asset['cvss'],0,10,'cvss') if asset.get('cvss','').strip() else None
    score,reasons=0,[]
    if kev:
        score+=40; reasons.append('CISA KEV confirms exploitation in the wild (+40)')
        if kev.get('ransomware'):
            score+=15; reasons.append('CISA reports ransomware use (+15)')
        if kev.get('epss') is not None:
            epss=number(kev['epss'],0,1,'epss')
            points=round(epss*15);score+=points
            reasons.append(f'EPSS {epss:.2%} as of {kev.get("epssDate")} (+{points})')
        else: reasons.append('EPSS unknown; no likelihood points assigned')
    else:reasons.append('No KEV match; absence is not evidence of safety')
    if asset['internet_exposed']=='true':
        score+=15;reasons.append('Inventory asserts internet exposure (+15)')
    points=criticality*3;score+=points
    reasons.append(f'Business criticality {criticality}/5 (+{points})')
    if cvss is not None: reasons.append(f'Inventory CVSS {cvss}/10; displayed separately from triage')
    return dict(asset=asset['asset'],cve=asset['cve'].upper(),score=score,
        priority='P1' if score>=70 else 'P2' if score>=45 else 'P3',
        kev=bool(kev),cvss=cvss,owner=asset.get('owner','Unassigned'),reasons=reasons,
        action=kev.get('action','Review vendor advisory and validate affected versions') if kev else 'Review vendor advisory and validate affected versions')

def correlate(inventory,intelligence):
    by_id={v['id']:v for v in intelligence['vulnerabilities']}
    results=[]
    seen=set()
    for asset in inventory:
        cve=asset['cve'].upper().strip();asset={**asset,'cve':cve}
        if not re.fullmatch(r'CVE-\d{4}-\d{4,8}',cve):raise ValueError('Invalid CVE: '+cve)
        key=(asset['asset'],cve)
        if key in seen:continue
        seen.add(key);results.append(triage(asset,by_id.get(cve)))
    return sorted(results,key=lambda r:(-r['score'],r['asset'],r['cve']))

def briefing(results,source_date):
    lines=['# Asset exposure review','',f'Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}',
        f'Intelligence collected: {source_date}','','## Decision summary',
        f'{len(results)} asset/CVE pairs reviewed; {sum(r["priority"]=="P1" for r in results)} meet the documented P1 threshold.',
        'The inventory is an analyst-supplied assertion of affected software. Confirm versions, exposure and compensating controls before action. This report is not evidence of compromise.','','## Findings']
    for r in results:
        lines.extend([f'### {r["priority"]} | {r["asset"]} | {r["cve"]}',f'Score: {r["score"]}/100; owner: {r["owner"]}; supplied CVSS: {r["cvss"] if r["cvss"] is not None else "unknown"}.',*['- '+x for x in r['reasons']],f'Recommended action: {r["action"]}',f'Reference: https://www.cve.org/CVERecord?id={r["cve"]}',''])
    lines.extend(['## Escalation and next steps','For confirmed high-priority exposure, notify the remediation owner and SOC with the affected asset, business impact, source evidence and validation status. Confirm patch status; review relevant telemetry and preserve evidence if suspicious activity is found.','','## Confidence and limitations','High confidence in a match to the supplied KEV snapshot; asset exposure depends on the inventory’s accuracy. EPSS is a model estimate, not proof of exploitation. Scores are an explicit portfolio heuristic, not CVSS or an enterprise risk standard. Missing enrichment never means zero risk.'])
    return '\n'.join(lines)+'\n'

def navigator_layer(intelligence,group_name):
    matches=[g for g in intelligence['groups'] if group_name.casefold() in [g['id'].casefold(),g['name'].casefold(),*[a.casefold() for a in g['aliases']]]]
    if len(matches)!=1:raise ValueError('Specify an exact, unambiguous ATT&CK group name, alias or ID')
    group=matches[0]
    return dict(name=f'{group["name"]} documented techniques',domain='enterprise-attack',
        description=f'Observed relationships from {group["url"]}. Collected {intelligence["collectedAt"]}. Not a detection coverage assessment.',
        techniques=[dict(techniqueID=t['id'],score=1,comment='Source: '+group['url']) for t in group['techniques']],
        gradient=dict(colors=['#ebf5f0','#167960'],minValue=0,maxValue=1))

def normalize_indicator(value):
    value=value.strip().replace('[.]','.').replace('hxxps://','https://').replace('hxxp://','http://')
    try:
        ip=ipaddress.ip_address(value)
        return ('ipv4-addr' if ip.version==4 else 'ipv6-addr',str(ip))
    except ValueError:pass
    if re.fullmatch(r'[a-fA-F0-9]{64}',value):return ('file',value.lower())
    if re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',value):return ('domain-name',value.lower())
    if re.fullmatch(r'https?://[^\s]+',value):return ('url',value)
    raise ValueError('Unsupported indicator')

def indicators_to_stix(values):
    now=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    objects=[];seen=set()
    for value in values:
        kind,value=normalize_indicator(value)
        if (kind,value) in seen:continue
        seen.add((kind,value))
        escaped=value.replace('\\','\\\\').replace("'","\\'")
        path="file:hashes.'SHA-256'" if kind=='file' else kind+':value'
        objects.append(dict(type='indicator',spec_version='2.1',id='indicator--'+str(uuid.uuid4()),
            created=now,modified=now,name=value,description='Analyst-supplied observable. Maliciousness has not been independently established.',
            pattern_type='stix',pattern=f"[{path} = '{escaped}']",valid_from=now))
    return dict(type='bundle',id='bundle--'+str(uuid.uuid4()),objects=objects)

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    t=s.add_parser('triage');t.add_argument('--intel',required=True);t.add_argument('--inventory',required=True);t.add_argument('--out',default='reports')
    n=s.add_parser('layer');n.add_argument('--intel',required=True);n.add_argument('--group',required=True);n.add_argument('--out',default='layer.json')
    i=s.add_parser('indicators');i.add_argument('--input',required=True);i.add_argument('--out',default='indicators.stix.json')
    a=p.parse_args()
    if a.command=='triage':
        intel=json.loads(Path(a.intel).read_text(encoding='utf-8'))
        with open(a.inventory,encoding='utf-8',newline='') as f:results=correlate(list(csv.DictReader(f)),intel)
        out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
        (out/'triage.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        (out/'brief.md').write_text(briefing(results,intel['collectedAt']),encoding='utf-8')
        print(f'Reviewed {len(results)} asset/CVE pairs. Reports: {out}')
    elif a.command=='layer':
        data=navigator_layer(json.loads(Path(a.intel).read_text(encoding='utf-8')),a.group)
        Path(a.out).write_text(json.dumps(data,indent=2),encoding='utf-8')
    else:
        data=indicators_to_stix(Path(a.input).read_text(encoding='utf-8').splitlines())
        Path(a.out).write_text(json.dumps(data,indent=2),encoding='utf-8')

if __name__=='__main__':main()
