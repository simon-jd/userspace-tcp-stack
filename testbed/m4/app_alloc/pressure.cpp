// Fixture only: constrain the real kernel TUN socket's send memory to exercise
// the nonblocking write / EPOLLOUT retry with production packets and syscalls.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
extern "C" ssize_t write(int fd,const void* data,size_t length) {
  static bool configured[64]{};
  if (fd>=0 && fd<64 && !configured[fd]) {
    const int saved=errno;
    char path[48], link[128];
    std::snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    const ssize_t n=readlink(path,link,sizeof(link));
    if (n==12 && !std::memcmp(link,"/dev/net/tun",12)) {
      int limit=4096;
      int actual=0;
      if (ioctl(fd,TUNSETSNDBUF,&limit)<0 || ioctl(fd,TUNGETSNDBUF,&actual)<0 || actual!=limit)
        _exit(124);
      constexpr char note[]="verified TUN send buffer = 4096\n";
      syscall(SYS_write,2,note,sizeof(note)-1);
      configured[fd]=true;
    }
    errno=saved;
  }
  return syscall(SYS_write,fd,data,length);
}
