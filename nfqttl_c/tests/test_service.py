"""Run the real shell supervisor against stateful Android/netfilter test doubles.
No host firewall, settings or /data changes. Does not simulate radio/driver behavior.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

MODULE = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
r=Path(os.environ['MOCK_ROOT']); name=Path(sys.argv[0]).name; a=sys.argv[1:]
if name=='owned-pid':
    # This container's mounted /proc is outside subprocess PID namespaces.
    # Model cmdline ownership explicitly; real service retains exact /proc checks.
    f=r/('cmdline.'+a[0])
    if not f.exists() or f.read_text()!=a[1]: sys.exit(1)
    try: os.kill(int(a[0]),0)
    except (OSError,ValueError): sys.exit(1)
    sys.exit()
if name=='getprop': print('1'); sys.exit()
if name=='ip':
    wifi=(r/'wifi').exists()
    if 'route' in a: print('default via 10.0.0.1 dev '+('wlan0' if wifi else 'rmnet_data0')+' table 100')
    else:
        print('1: ap0 inet 192.168.43.1/24 scope global ap0')
        print('2: '+('wlan0' if wifi else 'rmnet_data0')+' inet 10.0.0.2/24 scope global uplink')
    sys.exit()
if name in ('settings','device_config'):
    key='hw' if name=='settings' else 'bpf'; f=r/(key+'.json')
    value=json.loads(f.read_text()) if f.exists() else 'null'
    if a[0]=='get': print(value)
    elif a[0]=='put': f.write_text(json.dumps(a[-1]))
    elif a[0]=='delete': f.write_text(json.dumps('null'))
    sys.exit()
if name=='iptables':
    f=r/'rules.json'; db=json.loads(f.read_text())
    a=a[4:] # -w 2 -t mangle
    op=a[0]; c=a[1]; rule=a[2:]
    if op=='-N':
        if c in db: sys.exit(1)
        db[c]=[]
    elif op=='-F':
        if c not in db: sys.exit(1)
        db[c]=[]
    elif op=='-X':
        if c not in db: sys.exit(1)
        if db[c] or any(['-j',c]==x for rs in db.values() for x in rs): sys.exit(1)
        del db[c]
    elif op in ('-A','-I'):
        if c not in db: sys.exit(1)
        if op=='-I' and rule and rule[0].isdigit(): rule=rule[1:]
        if 'TTL' in rule and not (r/'native').exists(): sys.exit(1)
        if 'NFQUEUE' in rule and (r/'fail_rule').exists(): sys.exit(1)
        if op=='-I': db[c].insert(0,rule)
        else: db[c].append(rule)
    elif op in ('-C','-D'):
        if c not in db or rule not in db[c]: sys.exit(1)
        if op=='-D': db[c].remove(rule)
    elif op=='-R':
        if c not in db or not rule or not rule[0].isdigit(): sys.exit(1)
        pos=int(rule[0])-1; rule=rule[1:]
        if pos < 0 or pos >= len(db[c]): sys.exit(1)
        db[c][pos]=rule
    elif op in ('-S','-L'):
        if c not in db: sys.exit(1)
        print(db[c]);sys.exit()
    else: raise RuntimeError(a)
    f.write_text(json.dumps(db)); sys.exit()
raise RuntimeError(name)
'''
WORKER = r'''#!/usr/bin/env python3
import os, signal, time
from pathlib import Path
r=Path(os.environ['MOCK_ROOT']); f=r/'queue'
if (r/'fail_worker').exists(): raise SystemExit(1)
q=6464
if '-n' in sys.argv: q=int(sys.argv[sys.argv.index('-n')+1])
owner=r/('cmdline.'+str(os.getpid())); owner.write_text(str(Path(__file__).resolve()))
def stop(*args):
    f.write_text(''); owner.unlink(missing_ok=True); raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
f.write_text(f'{q} {os.getpid()} 0 2 65535 0 0 10 1\n')
print(f'READY queue={q} ttl=64 maxlen=1024 gso=1 pid={os.getpid()}',flush=True)
while True: time.sleep(0.1)
'''

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.r = Path(self.temp.name)
        self.m = self.r / 'module'
        self.m.mkdir()
        self.bin = self.r / 'bin'
        self.bin.mkdir()
        self.state = self.r / 'state'
        self.state.mkdir()
        for name in ('common.sh', 'service.sh', 'control.sh'):
            content = (MODULE / name).read_text()
            content = content.replace('/data/adb/nfqttl-state', str(self.state))
            content = content.replace('/proc/net/netfilter/nfnetlink_queue', str(self.r/'queue'))
            content = content.replace('/system/bin/iptables', str(self.bin/'iptables'))
            if name=='common.sh':
                start=content.index('owned_pid() {')
                end=content.index('\nqueue_owner()',start)
                content=content[:start]+'owned_pid() { "$MOCK_ROOT/bin/owned-pid" "$@"; }\n'+content[end:]
            (self.m/name).write_text(content)
        for name in ('iptables', 'getprop', 'ip', 'settings', 'device_config','owned-pid'):
            p = self.bin/name; p.write_text(MOCK); p.chmod(0o755)
        p = self.m/'nfqttl-lite'; p.write_text(WORKER); p.chmod(0o755)
        (self.r/'queue').write_text('')
        (self.r/'rules.json').write_text(json.dumps({'FORWARD': [['-j','android_fw']], 'android_fw': [['-j','RETURN']]}))
        (self.m/'config.conf').write_text('COOLDOWN=1\nMAX_FAILURES=1\nWORKERS=1\nIPV6_MODE=pass\nSTALL_LIMIT=2\n')
        self.env = dict(os.environ, MOCK_ROOT=str(self.r), PATH=str(self.bin)+':'+os.environ['PATH'])
        self.proc = None
        self.out = open(self.r/'stdout', 'w')

    def start(self):
        self.proc = subprocess.Popen(['sh',str(self.m/'service.sh')], env=self.env, stdout=self.out, stderr=self.out)
        (self.r/('cmdline.'+str(self.proc.pid))).write_text(str(self.m/'service.sh'))

    def wait_for(self, fn, timeout=15):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if fn(): return
            time.sleep(0.1)
        self.fail('timeout; '+(self.state/'service.log').read_text()+'\n'+(self.r/'stdout').read_text())

    def rules(self):
        try: return json.loads((self.r/'rules.json').read_text())
        except json.JSONDecodeError: return {}

    def active(self):
        return any('nfqttl_v30h' in ' '.join(x) for x in self.rules().get('FORWARD',[]))

    def assert_clean(self):
        db=self.rules()
        self.assertEqual(db['FORWARD'],[['-j','android_fw']])
        self.assertEqual(db['android_fw'],[['-j','RETURN']])
        self.assertFalse(any(x.startswith('nfqttl') for x in db))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate(); self.proc.wait(timeout=20)

    def tearDown(self):
        self.stop(); self.out.close(); self.temp.cleanup()

    def test_fallback_route_change_and_restore(self):
        self.start(); self.wait_for(self.active)
        self.assertEqual((self.state/'backend').read_text().strip(),'nfqueue')
        rules=str(self.rules())
        self.assertIn('rmnet_data0',rules)
        self.assertIn("'-i', 'ap0'",rules)
        (self.r/'wifi').touch()
        self.wait_for(lambda:'wlan0' in str(self.rules()) and 'rmnet_data0' not in str(self.rules()))
        self.assertNotIn('rmnet_data0',str(self.rules()))
        self.stop(); self.assert_clean()
        self.assertEqual(json.loads((self.r/'hw.json').read_text()),'null')
        self.assertEqual(json.loads((self.r/'bpf.json').read_text()),'null')

    def test_stalled_worker_opens_circuit(self):
        self.start(); self.wait_for(self.active)
        pid=(self.state/'worker.pid').read_text().strip()
        (self.r/'queue').write_text(f'6464 {pid} 1 2 65535 0 0 11 1\n')
        self.wait_for(lambda:self.proc.poll() is not None)
        self.assert_clean()
        self.assertIn('repeated backend failures',(self.state/'service.log').read_text())

    def test_worker_start_failure_never_attaches_rules(self):
        (self.r/'fail_worker').touch()
        self.start(); self.wait_for(lambda:self.proc.poll() is not None)
        self.assert_clean()

    def test_worker_death_detaches_rules(self):
        self.start(); self.wait_for(self.active)
        pid=int((self.state/'worker.pid').read_text().strip())
        os.kill(pid,signal.SIGTERM)
        self.wait_for(lambda:self.proc.poll() is not None)
        self.assert_clean()

    def test_duplicate_service_leaves_existing_instance(self):
        (self.r/'native').touch()
        self.start(); self.wait_for(self.active)
        pid=(self.state/'lock/pid').read_text()
        result=subprocess.run(['sh',str(self.m/'service.sh')],env=self.env,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0)
        self.assertEqual((self.state/'lock/pid').read_text(),pid)
        self.assertTrue(self.active())

    def test_partial_rule_failure_rolls_back(self):
        (self.r/'fail_rule').touch()
        self.start(); self.wait_for(lambda:self.proc.poll() is not None)
        self.assert_clean()

    def test_native_target_and_user_offload_override(self):
        (self.r/'native').touch()
        self.start(); self.wait_for(self.active)
        self.assertEqual((self.state/'backend').read_text().strip(),'kernel')
        self.assertIn('TTL',str(self.rules()))
        self.assertFalse((self.state/'worker.pid').exists())
        (self.r/'hw.json').write_text(json.dumps('0'))
        self.stop(); self.assert_clean()
        self.assertEqual(json.loads((self.r/'hw.json').read_text()),'0')

    def test_foreign_queue_is_not_taken_over(self):
        (self.r/'queue').write_text('6464 9999 0 2 65535 0 0 0 1\n')
        self.start(); self.wait_for(lambda:self.proc.poll() is not None)
        self.assert_clean()
        self.assertIn('9999',(self.r/'queue').read_text())

if __name__=='__main__': unittest.main(verbosity=2)
