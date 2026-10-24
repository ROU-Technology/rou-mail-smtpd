#!/usr/bin/env python3
"""Generate detailed service contracts from the canonical plan sources."""
import json,sys
from pathlib import Path
root=Path(__file__).resolve().parent.parent;plan=root/'docs/plan'
items=json.loads((plan/'backlog.json').read_text());details=json.loads((plan/'implementation-details.json').read_text())['features']
assert {x['id'] for x in items}==set(details)
for f in items:
 d=details[f['id']]
 assert len(d['flows'])>=4 and len(d['verification'])>=2
 out=f"# {f['id']}: {f['title']}\n\nStatus: **planned**. Phase: **HNR**. Product advancement: {f['advancement']}.\n\nImplementation acceptance remains unproven.\n"
 for title,key in [('Flows','flows'),('Data and state','data'),('Contracts','contracts'),('Permissions and isolation','permissions'),('Resource bounds','resource_controls'),('Library source and reuse','libraries'),('Failure and recovery','failure_recovery'),('Acceptance','verification'),('Test environments','test_environment'),('Reversal','migration_reversal')]:
  value=d[key];out+='\n## '+title+'\n\n'+('\n'.join('- '+str(x) for x in value) if isinstance(value,list) else value)+'\n'
 path=plan/f['file'];path.parent.mkdir(parents=True,exist_ok=True)
 if '--check' in sys.argv:assert path.read_text()==out,str(path)+' drift'
 else:path.write_text(out)
print(f'{len(items)} detailed service contracts verified')
