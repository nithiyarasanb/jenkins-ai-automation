#!/usr/bin/env python3
"""Generate a proposed unified diff using an OpenAI-compatible LiteLLM endpoint.
The output is untrusted and must be reviewed and tested before use.
"""
import argparse, json, os, re, sys, urllib.request, urllib.error
from pathlib import Path

SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', 'target', '.next', 'coverage', '__pycache__'}
SKIP_NAMES = {'.env', '.env.local', '.env.production', 'id_rsa', 'id_ed25519', 'credentials', 'secrets.yml', 'secret.yaml'}
ALLOWED_SUFFIXES = {'.java','.kt','.groovy','.xml','.gradle','.kts','.json','.js','.jsx','.ts','.tsx','.py','.toml','.yaml','.yml','.txt','.properties','.lock','.md'}

def safe_files(root: Path):
    result=[]
    for p in root.rglob('*'):
        if not p.is_file() or p.is_symlink(): continue
        rel=p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts): continue
        if p.name.lower() in SKIP_NAMES or p.name.startswith('.env'): continue
        if p.suffix.lower() not in ALLOWED_SUFFIXES: continue
        try:
            if p.stat().st_size > 100_000: continue
            text=p.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError): continue
        if re.search(r'(AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)', text): continue
        result.append((rel.as_posix(),text))
        if len(result) >= 80: break
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--findings',required=True); ap.add_argument('--repo',required=True); ap.add_argument('--output',required=True)
    ap.add_argument('--base-url',required=True); ap.add_argument('--model',required=True); ap.add_argument('--max-findings',type=int,default=10)
    a=ap.parse_args()
    key=os.environ.get('LITELLM_API_KEY')
    if not key: sys.exit('LITELLM_API_KEY is not set')
    data=json.loads(Path(a.findings).read_text())
    findings=[]
    for result in data.get('Results') or []:
        for v in result.get('Vulnerabilities') or []:
            if (v.get('Severity') or '').upper() not in ('CRITICAL','HIGH'): continue
            findings.append({k:v.get(k) for k in ('VulnerabilityID','PkgName','InstalledVersion','FixedVersion','Severity','Title','PrimaryURL','PkgPath','DataSource')})
    findings=findings[:a.max_findings]
    out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True)
    if not findings:
        out.write_text(''); print('No Critical/High findings; no AI patch requested.'); return
    files=safe_files(Path(a.repo).resolve())
    # Keep prompt bounded. Do not send the full repository or arbitrary binary/secret files.
    context='\n\n'.join(f'--- FILE: {name} ---\n{content[:12000]}' for name,content in files)
    system=('You are a cautious application security remediation assistant. Propose the smallest safe source/dependency change for the listed Critical/High vulnerabilities. '
      'Use only evidence in the supplied findings and files. Do not invent fixed versions. Respect dependency-management/BOM constraints. '
      'If the correct fix is uncertain, return an empty patch. Never include shell commands, credentials, or unrelated refactors. '
      'Return ONLY a unified git diff with paths relative to the repository, using a/ and b/ prefixes. No Markdown fences or explanation.')
    user='VULNERABILITY FINDINGS (scanner metadata is not proof that a version is compatible):\n'+json.dumps(findings,indent=2)+'\n\nSELECTED REPOSITORY FILES:\n'+context+'\n\nReturn only a unified diff. If you cannot make a justified safe fix, return an empty response.'
    url=a.base_url.rstrip('/')+'/chat/completions'
    payload=json.dumps({'model':a.model,'temperature':0,'messages':[{'role':'system','content':system},{'role':'user','content':user}]}).encode()
    req=urllib.request.Request(url,data=payload,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=120) as r: response=json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        sys.exit(f'LiteLLM request failed: {e}')
    patch=response['choices'][0]['message']['content'].strip()
    patch=re.sub(r'^```(?:diff|patch)?\s*|\s*```$','',patch,flags=re.I)
    # Reject non-diff content and suspicious paths before writing it.
    if patch and ('diff --git ' not in patch or re.search(r'(?m)^\+\+\+\s+.*(?:\.\./|/etc/|\.git/)',patch)):
        sys.exit('AI response was not an acceptable unified diff; refusing to write patch.')
    out.write_text(patch+'\n' if patch else '')
    print(f'AI proposal written to {out}; findings supplied: {len(findings)}; selected files: {len(files)}')
    print('WARNING: selected file contents and vulnerability metadata were sent to the configured LiteLLM endpoint.')
if __name__=='__main__': main()
