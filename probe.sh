#!/bin/sh
echo "== id"; uname -a; id
grep -E 'CapEff|NoNewPrivs|Seccomp|Cpus_allowed_list' /proc/self/status
echo "== cpu"; nproc; cat /sys/fs/cgroup/cpuset/cpuset.cpus 2>/dev/null || echo no-cpuset-v1
echo "== mem"; head -3 /proc/meminfo
for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/cpu/cpu.cfs_quota_us; do
  printf '%s = ' "$f"; cat "$f" 2>/dev/null || echo absent
done
echo "== alloc ladder (child, so OOM kills the child)"
for mb in 128 256 512 1024 2048; do
  timeout 25 python3 -c "
import mmap,sys
n=$mb*1024*1024
try:
    m=mmap.mmap(-1,n); m.write(b'\x41'*n)
    print('$mb MiB OK')
except Exception as e: print('$mb MiB FAIL',type(e).__name__)
" 2>&1 | tail -1
done
echo "== security"; cat /sys/kernel/security/lockdown 2>&1; ls /sys/kernel/security/ 2>&1 | head -6
echo "== btf"; ls -l /sys/kernel/btf/vmlinux 2>&1; head -c 8 /sys/kernel/btf/vmlinux 2>/dev/null | od -An -c 2>/dev/null | head -1
echo "== kptr"; cat /proc/sys/kernel/kptr_restrict 2>&1; cat /proc/sys/kernel/dmesg_restrict 2>&1; cat /proc/sys/kernel/unprivileged_userns_clone 2>&1
echo "== kallsyms"; head -2 /proc/kallsyms 2>&1
echo "== modules"; head -2 /proc/modules 2>&1
echo "== py"
python3 - <<'PY'
import socket,ctypes,os,struct
libc=ctypes.CDLL(None,use_errno=True)
p=ctypes.create_string_buffer(120)
r=libc.syscall(425,8,ctypes.byref(p)); print('io_uring_setup',r,'errno',libc.errno)
KS=-4
k=libc.syscall(248,b"user",b"probe",ctypes.c_void_p(5),ctypes.c_int(KS))
print('add_key',k,'errno',libc.errno)
print('unshare-UM', os.system('unshare -Um true 2>&1 >/dev/null'))
RR=bytes([0x07,0x07,0x04,0,0,0,0,0])
for host in ('192.168.32.1','172.31.0.1','147.5.115.161'):
    for opts,nm in ((None,'none'),(RR,'RR')):
        s=socket.socket(2,1); s.settimeout(4); s.setsockopt(0,7,1)
        try:
            if opts: s.setsockopt(0,4,opts)
            s.connect((host,22)); b=s.recv(48)
            print(host,nm,'banner',b[:18],'retopts',s.getsockopt(0,7,64).hex())
        except OSError as e: print(host,nm,'ERR',e.errno)
        finally: s.close()
ok=0
for i in range(500):
    try:
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        a.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,struct.pack('@i',b.fileno()))])
        a.close(); b.close(); ok+=1
    except Exception: break
print('af_unix scm loops',ok)
try:
    n=os.sched_setaffinity(0,{0,1}); print('affinity ok',sorted(n)[:4])
except Exception as e: print('affinity FAIL',e)
PY
echo "== done"
