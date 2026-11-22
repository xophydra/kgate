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

  hdr("done"); fflush(stdout);
  return 0;
}
