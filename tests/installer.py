#!/usr/bin/env python3
"""Exercise customize.sh with fake root-manager functions and host binary."""
import tempfile,subprocess,shutil
from pathlib import Path
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nfqttl-install-') as name:
 d=Path(name);old=d/'old.conf';stage=d/'stage';stage.mkdir();(stage/'libs/arm64-v8a').mkdir(parents=True)
 shutil.copy(root/'target/debug/nfqttl',stage/'libs/arm64-v8a/nfqttl')
 shutil.copy(root/'config.conf',stage/'config.conf')
 (stage/'webroot').mkdir()
 for f in ['service.sh','action.sh','control.sh','diagnose.sh','uninstall.sh']:shutil.copy(root/f,stage/f)
 original='TTL=65\nWORKERS=4\nIPV6_MODE=normalize\nDISABLE_OFFLOAD=0\nDOWNSTREAMS="wlan2"\n'
 old.write_text(original)
 customize=(root/'customize.sh').read_text().replace('OLD=/data/adb/modules/nfqttl/config.conf',f'OLD={old}')
 script=d/'run.sh';script.write_text(f'''#!/bin/sh
MODPATH={stage}
getprop() {{ echo arm64-v8a; }}
ui_print() {{ :; }}
abort() {{ echo "$*" >&2; exit 1; }}
set_perm_recursive() {{ :; }}
set_perm() {{ chmod "$4" "$1"; }}
'''+customize)
 r=subprocess.run(['sh',str(script)],capture_output=True,text=True);assert r.returncode==0,r.stderr
 final=(stage/'config.conf').read_text();assert 'TTL=65' in final and 'WORKERS=4' in final and 'IPV6_MODE=normalize' in final and 'DISABLE_OFFLOAD=0' in final
 assert 'IDLE_MS=10000' in final and 'GSO=0' in final and 'CHECK_MS=5000' in final
 assert old.read_text()==original
 assert (stage/'action.sh').stat().st_mode&0o777==0o755
 assert (stage/'config.conf').stat().st_mode&0o777==0o600
 print('PASS installer preserves existing values, appends defaults, validates config, sets permissions')
 # A malformed old config must cause abort without changing the installed file.
 old.write_text('TTL=0\n');(stage/'libs/arm64-v8a').mkdir(parents=True);shutil.copy(root/'target/debug/nfqttl',stage/'libs/arm64-v8a/nfqttl')
 r=subprocess.run(['sh',str(script)],capture_output=True,text=True);assert r.returncode!=0;assert old.read_text()=='TTL=0\n';print('PASS installer rejects invalid config without editing old installation')
