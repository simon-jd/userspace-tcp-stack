// Supplemental one-flow IPv4/TCPv4 TUN diagnostic. Successful real syscalls
// feed monotonic counters and per-second maxima; the external reader owns I/O.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
using U=uint64_t;
struct Row { U second, max_outstanding; };
struct Wire { U gso,segments,wire_tx,wire_rx; Row rows[64]; };
static Wire* w;
static int tun=-1;
static bool initialized;
static uint32_t high,acked;
static uint16_t be16(const unsigned char* p) { return uint16_t(p[0]<<8|p[1]); }
static uint32_t be32(const unsigned char* p) {return uint32_t(be16(p))<<16|be16(p+2);}
__attribute__((constructor)) static void initialize() {
  auto path=getenv("UTCP_NEW_COUNTER");
  char name[4096];
  if (!path || strlen(path)+6>sizeof(name)) _exit(125);
  strcpy(name,path); strcat(name,".wire");
  int fd=open(name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
  if (fd<0 || ftruncate(fd,sizeof(Wire))) _exit(125);
  w=static_cast<Wire*>(mmap(nullptr,sizeof(Wire),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0));
  if(w==MAP_FAILED) _exit(125);
  close(fd);
}
static void observe(int fd,const void* buf,ssize_t n,bool out){
  if(!w || n<50) return;
  if(tun<0){
    ifreq info{};
    int saved=errno;
    bool ok=ioctl(fd,TUNGETIFF,&info)==0 && !strcmp(info.ifr_name,"utcp0");
    errno=saved;
    if(!ok) return;
    tun=fd;
  }
  if(fd!=tun)return;
  const auto h=static_cast<const unsigned char*>(buf),ip=h+10;
  if(ip[0]>>4!=4||ip[9]!=6)return;
  const int ih=(ip[0]&15)*4;
  if(ih<20 || n<10+ih+20) return;
  const auto tcp=ip+ih;
  const int th=(tcp[12]>>4)*4;
  const int data=static_cast<int>(n)-10-ih-th;
  if(th<20 || data<0)return;
  if(out){
    ++w->wire_tx;
    if((h[1]&127)==1){
      const unsigned step=h[4]|h[5]<<8;
      if(!step) _exit(124);
      ++w->gso;
      w->segments+=(data+step-1)/step;
    }
    if(!initialized){
      if(!(tcp[13]&2)) return;
      high=acked=be32(tcp+4)+1; initialized=true;
    }
    if(data){
      const auto end=be32(tcp+4)+static_cast<uint32_t>(data);
      if(static_cast<int32_t>(end-high)>0) high=end;
    }
  } else {
    ++w->wire_rx;
    if(initialized && tcp[13]&16){
      const auto ack=be32(tcp+8);
      if(static_cast<int32_t>(ack-acked)>0 && static_cast<int32_t>(high-ack)>=0) acked=ack;
    }
  }
  if(initialized){
    timespec ts{};clock_gettime(CLOCK_MONOTONIC,&ts);
    auto& row=w->rows[ts.tv_sec%64];
    if(row.second!=static_cast<U>(ts.tv_sec)){row.second=ts.tv_sec;row.max_outstanding=0;}
    row.max_outstanding=std::max(row.max_outstanding,static_cast<U>(high-acked));
  }
}
extern "C" ssize_t write(int fd,const void* p,size_t size){
  auto n=syscall(SYS_write,fd,p,size);
  if(n>0) observe(fd,p,n,true);
  return n;
}
extern "C" ssize_t read(int fd,void* p,size_t size){
  auto n=syscall(SYS_read,fd,p,size);
  if(n>0) observe(fd,p,n,false);
  return n;
}
