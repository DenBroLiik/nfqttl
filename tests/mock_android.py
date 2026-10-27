#!/usr/bin/python3
"""Deterministic Android command simulator, not shipped as runtime code."""
import sys,json,os,fcntl
from pathlib import Path
base=Path(sys.argv[0]).parent
name=Path(sys.argv[0]).name
a=sys.argv[1:]
def load(n,default):
 try:return json.loads((base/n).read_text())
 except FileNotFoundError:return default

def save(n,v):
 q=base/(n+'.tmp');q.write_text(json.dumps(v));q.replace(base/n)
if name in ('iptables','ip6tables'):
 with (base/'fw.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  tables=load('fw.json',{'iptables':{'FORWARD':[]},'ip6tables':{'FORWARD':[]}})
  table=tables[name];a=a[4:];op=a[0];c=a[1] if len(a)>1 else '';r=a[2:];ok=True
  if op=='-N':
   ok=c not in table
   if ok:table[c]=[]
  elif op=='-F':
   ok=c in table
   if ok:table[c]=[]
  elif op=='-X':
   ok=c in table and not table[c] and not any(['-j',c]==x[-2:] for k in table for x in table[k])
   if ok:del table[c]
  elif op in ('-A','-I','-R'):
   ok=c in table
   if op=='-R':ok=ok and len(table[c])>=int(r[0])
   if ok:
    if op=='-A':table[c].append(r)
    elif op=='-I':table[c].insert(int(r[0])-1,r[1:])
    else:table[c][int(r[0])-1]=r[1:]
  elif op=='-C':ok=c in table and r in table[c]
  elif op=='-D':
   ok=c in table
   if r and r[0].isdigit():
    ok=ok and len(table[c])>=int(r[0])
    if ok:del table[c][int(r[0])-1]
   else:
    ok=ok and r in table[c]
    if ok:table[c].remove(r)
  elif op=='-S':
   ok=c in table if c else True
   if ok:
    for k in ([c] if c else table):
     print(('-P '+k+' ACCEPT') if k=='FORWARD' else '-N '+k)
     for x in table[k]:print('-A '+k+' '+' '.join(x))
  elif op=='-L':print('mock counters')
  else:ok=False
  save('fw.json',tables)
  if not ok:print('mock iptables failure',file=sys.stderr)
  sys.exit(0 if ok else 1)
elif name=='getprop':print('1' if a==['sys.boot_completed'] else 'moonstone')
elif name=='ip':
 n=load('network.json',{'up':'rmnet_data2','down':'wlan2','v6_only':False,'enabled':True})
 up=n['up'];down=n['down']
 if 'route' in a:
  if n['enabled'] and ('-6' in a or not n['v6_only']):print(f'default dev {up} table 100')
 elif 'addr' in a:
  if n['enabled']:print(f'12: {down} inet6 2001:db8::1/64 scope global' if n['v6_only'] else f'12: {down} inet 192.168.43.1/24 scope global {down}')
 elif 'link' in a:
  if n['enabled']:print(f'12: {down}: <UP> mtu 1500 state UP\n13: {up}: <UP> mtu 1500 state UNKNOWN')
elif name in ('settings','device_config'):
 with (base/'settings.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  values=load('settings.json',{'global/tether_offload_disabled':'0','connectivity/tether_enable_bpf_offload':'true','tethering/tether_enable_bpf_offload':'null'})
  op=a[0];key='/'.join(a[1:3])
  if op=='get':print(values.get(key,'null'))
  elif op=='put':values[key]=a[3]
  elif op=='delete':values[key]='null'
  save('settings.json',values)
else:sys.exit(1)
