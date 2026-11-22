"""Insert fixed-storage interval readers into temporary copies of the production drain and existing fixture."""
import argparse
from pathlib import Path
import subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("source",type=Path)
p.add_argument("out",type=Path)
a=p.parse_args()
src=a.source.resolve()
out=a.out.resolve()
out.mkdir(parents=True,exist_ok=True)
def edit(text,old,new):
    assert text.count(old)==1, old
    return text.replace(old,new)
probe=r'''
#include "common/utcp_transport.hpp"
#include <dlfcn.h>
#include <cstdio>
namespace branch_probe {
using U=uint64_t;
using Reader=void(*)(U*,U*);
inline Reader snapshot;
inline bool armed=false;
struct Item { U calls, bytes, blocked, sent; };
inline Item rows[256]{};
inline U count=0, send_calls=0, send_bytes=0, send_start_calls=0, send_start_bytes=0;
inline void begin(){
  snapshot=reinterpret_cast<Reader>(dlsym(RTLD_DEFAULT,"utcp_counter_read"));
  if(!snapshot) _Exit(125);
  armed=true; snapshot(&send_start_calls,&send_start_bytes);
}
inline void after_send(){
  snapshot(&send_calls,&send_bytes);
  send_calls-=send_start_calls;send_bytes-=send_start_bytes;
}
struct Scope {
  const utcp::app::DeviceStats& s; U calls{},bytes{},blocked{},sent{};
  explicit Scope(const utcp::app::DeviceStats& stats):s(stats) {
    if(armed){snapshot(&calls,&bytes); blocked=s.tx_eagain; sent=s.tx_datagrams;}
  }
  ~Scope(){
    if(!armed)return;
    U c,b; snapshot(&c,&b);
    if(count>=256) _Exit(124);
    rows[count++]={c-calls,b-bytes,s.tx_eagain-blocked,s.tx_datagrams-sent};
  }
};
inline void dump(){
  armed=false;
  std::printf("send calls=%llu bytes=%llu\n",(unsigned long long)send_calls,(unsigned long long)send_bytes);
  for(U i=0;i<count;++i){
    const auto& r=rows[i];
    std::printf("drain %llu calls=%llu bytes=%llu EAGAIN=%llu tx=%llu\n",(unsigned long long)i,
        (unsigned long long)r.calls,(unsigned long long)r.bytes,(unsigned long long)r.blocked,(unsigned long long)r.sent);
  }
}
}
'''
(out/"probe.hpp").write_text(probe)
transport=(src/"apps/common/utcp_transport.cpp").read_text()
transport=edit(transport,"void UtcpTransport::drain_tx() {","void UtcpTransport::drain_tx() {\n  branch_probe::Scope probe(dev_);")
(out/"transport.cpp").write_text('#include "probe.hpp"\n'+transport)
fixture=(src/"tests/interop/backend_transport_check.cpp").read_text()
fixture=edit(fixture,"  const auto sent = transport.send(h.selected, payload);","  branch_probe::begin();\n  const auto sent = transport.send(h.selected, payload);\n  branch_probe::after_send();")
fixture=edit(fixture,"  expect(full && sent && *sent == payload.size()", "  branch_probe::dump();\n  expect(full && sent && *sent == payload.size()")
fixture=fixture[:fixture.index("int main(int argc, char** argv)")]+"int main(){ check_multiqueue(); return failures!=0; }\n"
(out/"fixture.cpp").write_text('#include "probe.hpp"\n'+fixture)
b=src/"build/gcc-release"
cmd=["g++-15","-std=c++23","-O3","-DNDEBUG","-I"+str(src/"include"),"-I"+str(src/"apps"),"-I"+str(src/"src"),
    str(out/"fixture.cpp"),str(out/"transport.cpp"),str(b/"apps/common/libutcp_appkit.a"),
    str(b/"src/backend/libutcp_backend.a"),str(b/"src/core/libutcp_core.a"),"-ldl","-o",str(out/"check")]
subprocess.run(cmd,check=True)
