#!/usr/bin/env python3
import argparse, json
from pathlib import Path

def load(path):
    d=json.loads(Path(path).read_text()); out={}
    for r in d.get('Results') or []:
        for v in r.get('Vulnerabilities') or []:
            if (v.get('Severity') or '').upper() in ('CRITICAL','HIGH'):
                key=(v.get('VulnerabilityID',''),v.get('PkgName',''),v.get('InstalledVersion',''))
                out[key]={'severity':v.get('Severity',''),'fixed':v.get('FixedVersion',''),'target':r.get('Target','')}
    return out
p=argparse.ArgumentParser(); p.add_argument('--before',required=True); p.add_argument('--after',required=True); p.add_argument('--output',required=True); a=p.parse_args()
before,after=load(a.before),load(a.after)
removed=sorted(set(before)-set(after)); remaining=sorted(set(before)&set(after)); added=sorted(set(after)-set(before))
lines=['# CVE comparison','',f'- Before: {len(before)} Critical/High package-version findings',f'- After: {len(after)} Critical/High package-version findings',f'- No longer present in scan: {len(removed)}',f'- Still present: {len(remaining)}',f'- Newly reported: {len(added)}','','**Important:** absence from the after-scan is not by itself proof of remediation. Confirm the resolved dependency graph, runtime/container image, lockfiles, and scanner coverage.']
for title,items in [('No longer present',removed),('Still present',remaining),('Newly reported',added)]:
    lines += ['',f'## {title}']
    if not items: lines += ['None']
    for cve,pkg,ver in items:
        meta=(before if title!='Newly reported' else after).get((cve,pkg,ver),{})
        lines.append(f'- {meta.get("severity","?")} {cve} — {pkg} {ver}; target: {meta.get("target","?")}')
Path(a.output).write_text('\n'.join(lines)+'\n')
print(f'Wrote comparison to {a.output}')
