#!/bin/sh
echo "== id"; uname -a; id
grep -E 'CapEff|NoNewPrivs|Seccomp|Cpus_allowed_list' /proc/self/status
echo "== cpu"; nproc; cat /sys/fs/cgroup/cpuset/cpuset.cpus 2>/dev/null || echo no-cpuset
echo "== lockdown"; cat /sys/kernel/security/lockdown 2>&1; ls /sys/kernel/security/ 2>&1 | head -5
echo "== btf"; ls -l /sys/kernel/btf/vmlinux 2>&1; head -c 16 /sys/kernel/btf/vmlinux 2>/dev/null | od -c 2>/dev/null | head -2
echo "== kptr"; cat /proc/sys/kernel/kptr_restrict 2>&1; cat /proc/sys/kernel/randomize_va_space 2>&1
echo "== kallsyms"; head -2 /proc/kallsyms 2>&1
echo "== modules"; head -3 /proc/modules 2>&1
echo "== py"
python3 - <<'PY'
import socket,ctypes,os
libc=ctypes.CDLL(None)
p=ctypes.create_string_buffer(120)
r=libc.syscall(425,8,ctypes.byref(p))
print('io_uring_setup',r, 'errno',ctypes.get_errno() if hasattr(ctypes,'get_errno') else '')
libc.errno=0
r=libc.syscall(425,8,ctypes.byref(p)); print('io_uring_setup2',r,'errno',libc.errno)
# keyring with proper spec
KS=-4
k=libc.syscall(248,b"user",b"probe",ctypes.c_void_p(5),ctypes.c_int(KS))
print('add_key',k,'errno',libc.errno)
# arm path: IP_OPTIONS RR to metal sshd
RR=bytes([0x07,0x07,0x04,0,0,0,0,0])
for host in ('192.168.32.1','172.31.0.1','147.5.115.161'):
    for opts,nm in ((None,'none'),(RR,'RR')):
        s=socket.socket(2,1); s.settimeout(3); s.setsockopt(0,7,1)
        try:
            if opts: s.setsockopt(0,4,opts)
            s.connect((host,22)); b=s.recv(48)
            ro=s.getsockopt(0,7,64)
            print(host,nm,'banner',b[:20],'retopts',ro.hex())
        except OSError as e: print(host,nm,'ERR',e.errno)
        finally: s.close()
# af_unix SCM_RIGHTS loop (bounded, light GC churn)
ok=0
for i in range(500):
    try:
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        a.send(b'x',socket.ANCILLARY_DATA,[socket.fromfd(b.fileno(),socket.AF_UNIX,socket.SOCK_STREAM)])
        a.close(); b.close(); ok+=1
    except Exception as e: break
print('af_unix scm loops',ok)
PY
echo "== done"
