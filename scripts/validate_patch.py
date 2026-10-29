#!/usr/bin/env python3
import argparse, subprocess, sys
from pathlib import Path

BLOCKED = ('../', '/etc/', '/proc/', '/sys/', '.git/', '.env', 'id_rsa', 'id_ed25519')
def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo',required=True); ap.add_argument('--patch',required=True); a=ap.parse_args()
    repo=Path(a.repo).resolve(); patch=Path(a.patch).resolve()
    raw=patch.read_text(errors='replace')
    if not raw.strip(): print('Empty patch; nothing to apply.'); return
    if not raw.startswith('diff --git '): sys.exit('Patch rejected: missing unified git diff header.')
    for line in raw.splitlines():
        if line.startswith(('+++ ', '--- ')):
            path=line[4:].split('\t')[0]
            if path == '/dev/null': continue
            clean=path[2:] if path.startswith(('a/','b/')) else path
            if clean.startswith('/') or any(x in clean for x in BLOCKED): sys.exit(f'Patch rejected due to unsafe path: {path}')
            resolved=(repo/clean).resolve()
            if resolved != repo and repo not in resolved.parents: sys.exit(f'Patch path escapes repository: {path}')
    check=run(['git','apply','--check','--whitespace=error',str(patch)],repo)
    if check.returncode: sys.exit('Patch does not apply cleanly:\n'+check.stdout)
    # The checked patch is applied only inside this build workspace, not pushed to remote.
    applied=run(['git','apply','--whitespace=error',str(patch)],repo)
    if applied.returncode: sys.exit('Patch application failed:\n'+applied.stdout)
    status=run(['git','diff','--check'],repo)
    if status.returncode: sys.exit('Whitespace/conflict check failed:\n'+status.stdout)
    print('Patch applied in workspace and passed git diff --check. It has not been committed or pushed.')
if __name__=='__main__': main()
