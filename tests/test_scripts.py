import json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ScriptTests(unittest.TestCase):
 def test_summary_empty(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/'in.json'; out=Path(d)/'out.md'; src.write_text(json.dumps({'Results':[]}))
   subprocess.run([sys.executable,str(ROOT/'scripts/summarize_findings.py'),str(src),str(out)],check=True)
   self.assertIn('Total Critical/High findings: **0**',out.read_text())
 def test_compare_empty(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'b.json'; a=Path(d)/'a.json'; o=Path(d)/'o.md'
   b.write_text(json.dumps({'Results':[]})); a.write_text(json.dumps({'Results':[]}))
   subprocess.run([sys.executable,str(ROOT/'scripts/compare_cves.py'),'--before',str(b),'--after',str(a),'--output',str(o)],check=True)
   self.assertIn('absence from the after-scan is not by itself proof',o.read_text())
if __name__=='__main__': unittest.main()
