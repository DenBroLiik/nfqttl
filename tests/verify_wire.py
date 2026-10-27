#!/usr/bin/env python3
"""Live AF_PACKET check of `nfqttl verify --wire-only` on the loopback device.

Needs CAP_NET_RAW (root). Skips, rather than fails, when packet sockets are
unavailable. No firewall or system setting is touched.
"""
import os, sys, socket, subprocess, tempfile, threading, time, shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bin = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / 'target/debug/nfqttl'


def packet_sockets_available():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        s.close()
        return True
    except OSError:
        return False


def send_udp(ttl, count):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    for _ in range(count):
        u.sendto(b'nfqttl-verify', ('127.0.0.1', 40123))
        time.sleep(0.005)
    u.close()


def run_verify(mod, state, traffic):
    env = dict(os.environ, NFQTTL_STATE=str(state))
    p = subprocess.Popen(
        [str(bin), 'verify', '--wire-only', '--iface', 'lo', '--seconds', '3',
         '--module-dir', str(mod)],
        env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.8)  # let the tap open before sending
    threads = [threading.Thread(target=send_udp, args=t) for t in traffic]
    [t.start() for t in threads]
    [t.join() for t in threads]
    out, err = p.communicate(timeout=30)
    return p.returncode, out, err


if not packet_sockets_available():
    print('SKIP AF_PACKET unavailable (needs root/CAP_NET_RAW)')
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix='nfqttl-wire-') as d:
    d = Path(d)
    mod, state = d / 'module', d / 'state'
    mod.mkdir()
    shutil.copy(root / 'config.conf', mod / 'config.conf')
    # config.conf ships TTL=64; the default phone TTL on this host is 64 too.

    rc, out, err = run_verify(mod, state, [(64, 60)])
    assert rc == 0, (rc, out, err)
    assert 'VERIFY_RESULT=PASS' in out and '64x' in out, out
    print('PASS wire-only: normalised TTL 64 traffic passes')

    rc, out, err = run_verify(mod, state, [(64, 60), (63, 60)])
    assert rc == 3, (rc, out, err)
    assert 'VERIFY_RESULT=FAIL' in out and '63x' in out, out
    assert 'Foreign IPv4 TTL' in out, out
    print('PASS wire-only: TTL 63 leak is reported as FAIL (exit 3)')

    # A few odd packets must not fail the check (noise tolerance).
    rc, out, err = run_verify(mod, state, [(64, 200), (63, 5)])
    assert rc == 0, (rc, out, err)
    print('PASS wire-only: 5 stray odd-TTL packets among 200 are tolerated')

    rc, out, err = run_verify(mod, state, [])
    assert rc in (0, 2) and 'VERIFY_RESULT=' in out, (rc, out, err)
    assert rc != 3
    print('PASS wire-only: idle link never produces a false FAIL')

    # Unknown interface degrades gracefully instead of crashing.
    env = dict(os.environ, NFQTTL_STATE=str(state))
    r = subprocess.run(
        [str(bin), 'verify', '--wire-only', '--iface', 'nfqttl_nope0', '--seconds', '2',
         '--module-dir', str(mod)], env=env, text=True, capture_output=True, timeout=30)
    assert r.returncode == 2 and 'Wire sampling unavailable' in r.stdout, (r.returncode, r.stdout)
    print('PASS missing interface degrades to INCONCLUSIVE with an explanation')

    r = subprocess.run([str(bin), 'verify', '--seconds', '1', '--module-dir', str(mod)],
                       env=env, text=True, capture_output=True, timeout=30)
    assert r.returncode == 1 and 'error' in (r.stderr + r.stdout).lower() or 'nfqttl:' in r.stderr, r
    print('PASS invalid --seconds is rejected')

print('VERIFY WIRE TESTS PASSED')
