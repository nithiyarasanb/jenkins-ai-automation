#!/usr/bin/env python3
import json, sys
from pathlib import Path

src, out = map(Path, sys.argv[1:3])
data = json.loads(src.read_text()) if src.exists() else {}
rows = []
for result in data.get('Results') or []:
    target = result.get('Target', 'unknown')
    for v in result.get('Vulnerabilities') or []:
        sev = (v.get('Severity') or 'UNKNOWN').upper()
        if sev not in ('CRITICAL', 'HIGH'):
            continue
        rows.append((sev, v.get('VulnerabilityID',''), v.get('PkgName',''), v.get('InstalledVersion',''), v.get('FixedVersion',''), target, v.get('Title','')))
rows.sort(key=lambda r: (0 if r[0]=='CRITICAL' else 1, r[1], r[2]))
lines = ['# Critical/High vulnerability summary', '', f'Total Critical/High findings: **{len(rows)}**', '', '| Severity | CVE | Package | Installed | Fixed version (scanner metadata) | Target |', '|---|---|---|---|---|---|']
for sev,cve,pkg,installed,fixed,target,title in rows:
    vals = [sev,cve,pkg,installed,fixed,target]
    vals = [str(x).replace('|','\\|').replace('\n',' ') for x in vals]
    lines.append('| ' + ' | '.join(vals) + ' |')
if not rows: lines += ['No Critical/High findings were reported by Trivy. This does not prove the application is vulnerability-free; review scan coverage and SBOM scope.']
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text('\n'.join(lines) + '\n')
print(f'Wrote {len(rows)} findings to {out}')
