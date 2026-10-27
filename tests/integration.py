#!/usr/bin/env python3
"""Host integration tests with isolated fake Android/netd commands.
No phone, root firewall changes, or network traffic are required.
"""
import os,sys,json,tempfile,subprocess,time,fcntl,shutil
from pathlib import Path
root=Path(__file__).resolve().parents[1]
bin=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else root/'target/debug/nfqttl'
def wait(test,desc,timeout=12):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  try:
   if test():print('PASS',desc);return
  except (FileNotFoundError,json.JSONDecodeError,KeyError,AssertionError,IndexError):pass
  time.sleep(.1)
 raise AssertionError(desc)
with tempfile.TemporaryDirectory(prefix='nfqttl-test-') as temp:
 d=Path(temp);state=d/'state';mod=d/'module';mod.mkdir()
 for name in ('iptables','ip6tables','ip','getprop','settings','device_config'):
  shutil.copy(root/'tests/mock_android.py',d/name);(d/name).chmod(0o755)
 shutil.copy(root/'config.conf',mod/'config.conf')
 with (mod/'config.conf').open('a') as f:f.write('\nCHECK_MS=1000\nRESCAN_MS=1000\nIDLE_MS=1000\n')
 # Replace settings rather than creating ambiguous duplicate keys.
 lines=(mod/'config.conf').read_text().splitlines();seen=set();out=[]
 for line in reversed(lines):
  key=line.split('=',1)[0]
  if '=' not in line or key not in seen:out.append(line)
  seen.add(key)
 (mod/'config.conf').write_text('\n'.join(reversed(out))+'\n')
 env=dict(os.environ,PATH=str(d)+':'+os.environ['PATH'],NFQTTL_STATE=str(state),NFQTTL_IPTABLES=str(d/'iptables'),NFQTTL_IP6TABLES=str(d/'ip6tables'))
 def cli(*args):return subprocess.run([str(bin),*args,'--module-dir',str(mod)],env=env,text=True,capture_output=True,timeout=50)
 def fw():return json.loads((d/'fw.json').read_text())
 def edit_fw(fn):
  with (d/'fw.lock').open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX);j=fw();fn(j);(d/'fw.json').write_text(json.dumps(j))
 def active():return (state/'phase').read_text()=='active'
 def good():
  j=fw()
  for family,hook in [('iptables','nfqttl_v40h'),('ip6tables','nfqttl6_v40h')]:
   table=j[family];assert table['FORWARD'][0]==['-j',hook]
   assert len([r for r in table['FORWARD'] if r==['-j',hook]])==1
   target=table[hook][0][-1];assert table[target]
  return True
 assert cli('check').returncode==0
 daemon=subprocess.Popen([str(bin),'daemon','--module-dir',str(mod)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:
  wait(lambda:active() and good(),'kernel IPv4+IPv6 rules installed')
  assert (state/'workers').read_text()=='0';print('PASS kernel path launches zero queue workers')
  second=cli('daemon');assert second.returncode==0 and daemon.poll() is None;print('PASS duplicate daemon does not take ownership')
  # Flush only the payload chains: a hook existence check would miss this.
  edit_fw(lambda j:[j[f].__setitem__(j[f][h][0][-1],[]) for f,h in [('iptables','nfqttl_v40h'),('ip6tables','nfqttl6_v40h')]])
  wait(good,'recovers flushed payload chains')
  edit_fw(lambda j:[j[f].__setitem__(h,[]) for f,h in [('iptables','nfqttl_v40h'),('ip6tables','nfqttl6_v40h')]])
  wait(good,'recovers empty hook chains')
  edit_fw(lambda j:j['iptables']['FORWARD'].append(['-j','nfqttl_v40h']))
  wait(good,'removes duplicate forwarding hooks')
  (d/'network.json').write_text(json.dumps({'up':'rmnet_data3','down':'rndis0','v6_only':True,'enabled':True}))
  wait(lambda:active() and 'rndis0' in (state/'interfaces').read_text() and 'rmnet_data3' in (state/'interfaces').read_text() and good(),'IPv6-only upstream and USB route switch')
  (d/'network.json').write_text(json.dumps({'up':'rmnet_data3','down':'rndis0','v6_only':True,'enabled':False}))
  wait(lambda:(state/'phase').read_text()=='idle' and not fw()['iptables']['FORWARD'],'removes rules when tether interfaces disappear')
  assert cli('stop').returncode==0
  daemon.wait(timeout=4)
  values=json.loads((d/'settings.json').read_text());assert values=={'global/tether_offload_disabled':'0','connectivity/tether_enable_bpf_offload':'true','tethering/tether_enable_bpf_offload':'null'};print('PASS restores all original offload settings')
  assert (state/'paused').exists();print('PASS persistent pause survives service launch')
  assert cli('daemon').returncode==0;assert not (state/'lock/pid').exists()
  assert cli('start').returncode==0
  wait(lambda:(state/'lock/pid').exists(),'start clears pause and starts supervisor')
  assert cli('configure','TTL=65','BACKEND=kernel','WORKERS=2').returncode==0
  wait(lambda:'TTL=65' in cli('snapshot').stdout and (state/'lock/pid').exists(),'atomic config save and daemon restart')
  assert (mod/'config.conf.bak').exists()
  assert cli('configure','TTL=0').returncode!=0
  assert 'TTL=65' in (mod/'config.conf').read_text();print('PASS rejected setting leaves config unchanged')
  values=json.loads((d/'settings.json').read_text());values['global/tether_offload_disabled']='0';(d/'settings.json').write_text(json.dumps(values))
  assert cli('stop').returncode==0
  assert json.loads((d/'settings.json').read_text())['global/tether_offload_disabled']=='0';print('PASS offload restore preserves external setting changes')
  # Invalid configurations must be rejected before stopping a running daemon.
  with (mod/'config.conf').open('a') as f:f.write('TTL=0\n')
  assert cli('check').returncode!=0;assert cli('start').returncode!=0;print('PASS invalid/duplicate settings rejected')
 finally:
  if daemon.poll() is None:daemon.terminate();daemon.wait(timeout=50)
  pidfile=state/'lock/pid'
  if pidfile.exists():
   try:os.kill(int(pidfile.read_text()),15)
   except ProcessLookupError:pass
print('ALL INTEGRATION TESTS PASSED')
