#include "windows.hpp"
#include "utcp/stack.hpp"
#include "support/packet_builder.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>

using namespace utcp;
using namespace std::chrono_literals;
namespace {
Windows win;
std::FILE* wire_file;
std::FILE* event_file;
std::FILE* tx_file;
struct Sink final : TraceSink {
  std::array<std::uint64_t,32> kinds{};
  unsigned fired_rto{},fired_delack{};
  void on_event(const TraceEvent& e) override {
    ++kinds.at(static_cast<unsigned>(e.kind));
    if (e.kind==TraceKind::timer && e.timer_op==TimerOp::fired) {
      fired_rto += e.timer==TraceTimer::rto;
      fired_delack += e.timer==TraceTimer::delack;
    }
  }
};
using Mode=std::string_view;
struct Pair {
  Mode mode;
  Sink sink;
  StackConfig ac,bc;
  std::optional<Stack> a,b;
  Handle client{},server{},listener{};
  Endpoint peer{Ipv4Addr{0xc0000202},8000};
  Time now{1'000'000'000};
  std::uint64_t gso{},ordinary{},blocked{},would_block{},reorders{},losses{},timer_wakes{};
  unsigned full_packets_after_gso{}, last_gso_stride{};
  unsigned timer_drops{};
  bool inject{};
  unsigned pmtu_count{}, expired{}, duplicate_count{}, wake_count{};
  std::array<Handle,2> waiter{}, child{};
  bool checking_wakes{};
  Pair(Mode m,bool trace) : mode(m) {
    ac.local_addr=Ipv4Addr{0xc0000201};
    ac.tcp.cc=CcAlgo::cubic;
    ac.tcp.nodelay=true;
    ac.tcp.initial_cwnd=32;
    if (m=="pmtu") ac.tcp.pmtu_expiry=2s;
    ac.max_connections=32;
    ac.pool_buffers=m=="pool_pressure" ? 2 : 128;
    if (m=="delack") ac.tcp.quickack=Quickack::rfc;
    ac.tx_queue_packets=m=="tx_pressure" ? 2 : 64;
    ac.chunk_limit=m=="chunk_pressure" || m=="multi_waiter" ? 2 : 128;
    if (m=="gso" || m=="fallback") {
      ac.tcp_checksum_offload=true;
      ac.tcp_gso_buffers=m=="fallback" ? 1 : 16;
      if (m=="fallback") ac.tcp.gso_max_size=5840;
    }
    ac.trace_mask=trace ? trace_mask_all : 0;
    bc=ac;
    bc.local_addr=peer.addr;
    win.run(stack_ctor,[&]{a.emplace(ac);});
    win.run(stack_ctor,[&]{b.emplace(bc);});
    if (trace) {a->set_trace_sink(&sink); b->set_trace_sink(&sink);}
  }
  std::optional<TxPacket> pop(Stack& src) {
    auto packet=win.run(pop_,[&]{return src.pop_transmit();});
    if (packet) {
      const auto bytes=packet->buf.bytes();
      const auto ihl=(std::to_integer<unsigned>(bytes[0])&15)*4;
      const auto tcp=std::to_integer<unsigned>(bytes[9])==6;
      const auto l4=tcp ? (std::to_integer<unsigned>(bytes[ihl+12])>>4)*4 : 8u;
      const auto payload=bytes.size()-ihl-l4;
      auto& row=win.row(pop_);
      ++row.packets; row.bytes+=payload;
      row.segments+=packet->gso_size && payload ? 1+(payload-1)/packet->gso_size : 1;
      const std::array<std::uint64_t,6> header{(unsigned)win.phase,&src==&*a,
          (std::uint64_t)now.ns,bytes.size(),packet->gso_size,packet->csum_partial};
      require(std::fwrite(header.data(),sizeof(header),1,tx_file)==1 &&
              std::fwrite(bytes.data(),bytes.size(),1,tx_file)==1,"TX transcript");
    }
    return packet;
  }
  void deliver(TxPacket& p,Stack& dst,bool forward,bool release=true) {
    auto bytes=p.buf.bytes();
    require(bytes.size()>=20,"IPv4 header");
    auto u=[&](std::size_t i){return std::to_integer<unsigned>(bytes[i]);};
    const auto ihl=4*(u(0)&15); unsigned payload=0,segments=1;
    Path path=control_;
    if (u(9)==6) {
      require(bytes.size()>=ihl+20,"TCP header");
      const auto thl=4*(u(ihl+12)>>4);
      require(bytes.size()>=ihl+thl,"TCP payload length");
      payload=bytes.size()-ihl-thl;
      path=payload ? data_ : (u(ihl+13)==16 ? ack_ : control_);
      if (p.gso_size && payload) { last_gso_stride=p.gso_size; segments=(payload-1)/p.gso_size+1; ++gso; }
      if (!p.gso_size && payload) { ++ordinary; if (forward && last_gso_stride==payload) ++full_packets_after_gso; }
    } else if (u(9)==17 || u(9)==1) {
      require(bytes.size()>=ihl+8,"datagram length");
      payload=bytes.size()-ihl-8;
      path=u(9)==17 ? udp_in_ : echo_in_;
    }
    auto& row=win.row(path);
    ++row.packets; row.segments+=segments; row.bytes+=payload;
    // Fixed, explicitly typed transcript includes descriptor boundaries,
    // direction, time and offload metadata as observed by the peer.
    const std::array<std::uint64_t,6> h{
        static_cast<unsigned>(win.phase),forward,static_cast<std::uint64_t>(now.ns),
        bytes.size(),p.gso_size,p.csum_partial};
    require(std::fwrite(h.data(),sizeof(h),1,wire_file)==1 &&
            std::fwrite(bytes.data(),bytes.size(),1,wire_file)==1,"write transcript");
    win.run(path,[&]{dst.receive(now,bytes,RxMeta{.csum_partial=p.csum_partial,.gso_size=p.gso_size});});
    if (release) win.run(release_,[&]{p.buf.reset();});
  }
  bool drain(Stack& src,Stack& dst,bool forward) {
    bool active=false;
    last_gso_stride=0;
    while (auto packet=pop(src)) {
      active=true;
      if (forward && timer_drops) {
        --timer_drops;
        ++losses;
        win.run(release_,[&]{packet->buf.reset();});
        continue;
      }
      if (forward && inject && mode=="pmtu") {
        inject=false;
        // The router reports its lower MTU for the actual first data datagram.
        const auto mtu=static_cast<std::uint16_t>(1400 - 8*pmtu_count);
        auto message=test::icmp_error(Ipv4Addr{0xc00002fe},ac.local_addr,
            wire::icmp_dest_unreach,wire::icmp_frag_needed,mtu,packet->buf.bytes(),28);
        win.run(release_,[&]{packet->buf.reset();});
        win.run(pmtu_,[&]{src.receive(now,message);});
        require(src.tcp_info(client)->pmtu==mtu && src.debug_usage().stack_timers_armed>0,"applied ICMP PMTU");
        ++pmtu_count;
        continue;
      }
      if (forward && inject && mode=="duplicate") {
        inject=false;
        deliver(*packet,dst,forward,false);
        ++duplicate_count;
      }
      if (forward && inject && (mode=="reorder" || mode=="loss")) {
        inject=false;
        if (mode=="loss") {
          ++losses;
          win.run(release_,[&]{packet->buf.reset();});
          continue;
        }
        auto later=pop(src);
        require(bool(later),"second packet for reorder");
        deliver(*later,dst,forward);
        ++reorders;
      }
      deliver(*packet,dst,forward);
    }
    return active;
  }
  void events(Stack& s,bool forward) {
    while (auto e=win.run(event_,[&]{return s.poll_event();})) {
      if (checking_wakes && forward && (e->events & ev_writable) &&
          (e->h==waiter[0] || e->h==waiter[1])) {
        require(wake_count<2 && e->h==waiter[wake_count],"waiter FIFO order");
        ++wake_count;
      }
      require(std::fprintf(event_file,"%d,%lld,%u,%u,%u,%u\n",forward,
          (long long)now.ns,e->h.slot,e->h.gen,e->events,(unsigned)win.phase)>0,"event transcript");
    }
  }
  void pump() {
    for (unsigned i=0;i<1000;++i) {
      bool ab=drain(*a,*b,true),ba=drain(*b,*a,false);
      events(*a,true); events(*b,false);
      if (!ab && !ba) return;
    }
    require(false,"drain bound");
  }
  void advance(Time t) {
    require(!t.is_never() && t>=now,"finite next deadline");
    now=t;
    win.run(advance_,[&]{a->advance(t);}); win.run(advance_,[&]{b->advance(t);});
  }
  void deadline() {
    auto ta=win.run(next_,[&]{return a->next_deadline();});
    auto tb=win.run(next_,[&]{return b->next_deadline();});
    ++timer_wakes;
    advance(std::min(ta,tb));
  }
  void connect() {
    advance(now);
    listener=win.run(listen_,[&]{return b->tcp_listen(peer,4);}).value();
    client=win.run(connect_,[&]{return a->tcp_connect(peer);}).value();
    pump();
    server=win.run(accept_,[&]{return b->tcp_accept(listener);}).value();
  }
  void open_waiters() {
    for (unsigned i=0;i<2;++i) {
      waiter[i]=win.run(connect_,[&]{return a->tcp_connect(peer);}).value();
      pump();
      child[i]=win.run(accept_,[&]{return b->tcp_accept(listener);}).value();
    }
  }
  void multi_waiter(std::span<const std::byte> data) {
    auto fill=data.first(2*ring_chunk_bytes);
    require(win.run(send_,[&]{return a->tcp_send(client,fill);}).value()==fill.size(),"hold two chunks");
    win.row(send_).bytes+=fill.size();
    wake_count=0;
    for (const auto h:waiter) {
      auto blocked=win.run(send_,[&]{return a->tcp_send(h,data.first(1));});
      require(!blocked && blocked.error()==Error::would_block,"waiter genuinely blocked");
      ++would_block;
    }
    checking_wakes=true;
    for (unsigned step=0;step<10 && wake_count!=2;++step) {
      pump();
      if (wake_count!=2) deadline();
    }
    require(wake_count==2,"both waiters notified");
    checking_wakes=false;
    std::array<std::byte,2*ring_chunk_bytes> got{};
    require(win.run(recv_,[&]{return b->tcp_recv(server,got);}).value()==got.size() &&
            std::equal(got.begin(),got.end(),fill.begin()),"exact held payload");
    win.row(recv_).bytes+=got.size();
    for (unsigned i=0;i<2;++i) transfer(*a,waiter[i],*b,child[i],data.subspan(i,64));
  }
  void transfer(Stack& src,Handle from,Stack& dst,Handle to,std::span<const std::byte> data) {
    std::array<std::byte,32768> read{};
    std::size_t sent=0,received=0;
    for (unsigned step=0;step<10000;++step) {
      bool progress=false;
      if (sent<data.size()) {
        auto v=win.run(send_,[&]{return src.tcp_send(from,data.subspan(sent));});
        if (v) {
          require(*v>0,"positive send");
          sent+=*v; win.row(send_).bytes+=*v; progress=true;
          if (sent<data.size() && mode=="chunk_pressure") {
            auto w=win.run(send_,[&]{return src.tcp_send(from,data.subspan(sent));});
            require(!w && w.error()==Error::would_block,"chunk refusal before drain");
            ++would_block;
          }
        } else {
          require(v.error()==Error::would_block,"ordinary blocked send"); ++would_block;
        }
      }
      if (src.debug_usage().blocked_conns) ++blocked;
      pump();
      if (mode=="delack" && received<sent && src.tcp_info(from)->unacked) {
        // A receiver that has not yet consumed the data can take its normal
        // delayed-ACK deadline. Application read follows the ACK transmission.
        deadline();
        pump();
      }
      while (received<sent) {
        auto v=win.run(recv_,[&]{return dst.tcp_recv(to,read);});
        if (!v) { require(v.error()==Error::would_block,"ordinary blocked read"); break; }
        require(*v>0 && *v<=sent-received && std::equal(read.begin(),read.begin()+*v,data.begin()+received),"exact stream bytes");
        received+=*v; win.row(recv_).bytes+=*v; progress=true;
      }
      pump();  // drain window updates before checking for the next wakeup
      auto info=win.run(info_,[&]{return src.tcp_info(from);});
      require(bool(info),"live sender info");
      auto ready=win.run(ready_,[&]{return src.tcp_readiness(from);});
      if (received==data.size() && !info->unacked && sent==data.size()) {
        require(ready.writable,"writable after full drain"); return;
      }
      if (received < sent && win.run(ready_,[&]{return dst.tcp_readiness(to);}).readable) continue;
      if (!progress || sent==data.size()) deadline();
      else advance(now+100us);
    }
    require(false,"completed transfer");
  }
  void ip(unsigned round,std::span<const std::byte> payload) {
    if (mode=="udp") {
      require(bool(win.run(udp_send_,[&]{return a->udp_send_to(client,peer,payload);})),"UDP send");
      win.row(udp_send_).bytes+=payload.size(); pump();
      std::array<std::byte,1400> got{};
      auto d=win.run(udp_recv_,[&]{return b->udp_recv_from(server,got);});
      require(d && !d->truncated && d->from==Endpoint{ac.local_addr,4000} &&
              d->len==payload.size() && std::equal(payload.begin(),payload.end(),got.begin()),"UDP payload and source");
      win.row(udp_recv_).bytes+=d->len;
    } else {
      require(bool(win.run(echo_send_,[&]{return a->icmp_echo(peer.addr,15,round,payload);})),"ICMP send");
      win.row(echo_send_).bytes+=payload.size();pump();
      auto r=win.run(echo_poll_,[&]{return a->poll_echo_reply();});
      require(r && r->len==payload.size() && r->id==15 && r->seq==round && r->from==peer.addr,"ICMP reply");
      win.row(echo_poll_).bytes+=r->len;
    }
  }
};
}

int main(int argc,char** argv) {
  require(argc==7,"usage: MODE {off|count} {count|sites} WIRE EVENT TX");
  Mode mode=argv[1]; bool trace=Mode(argv[2])=="count";
  require(trace || Mode(argv[2])=="off","trace switch");
  wire_file=std::fopen(argv[4],"wb"); event_file=std::fopen(argv[5],"w");
  tx_file=std::fopen(argv[6],"wb");
  require(wire_file && event_file && tx_file,"transcript files");
  utcp_heap_sites(Mode(argv[3])=="sites");
  Pair p(mode,trace);
  bool is_ip=mode=="udp" || mode=="icmp";
  if (!is_ip) p.connect();
  if (mode=="multi_waiter") p.open_waiters();
  if (mode=="udp") {
    p.client=win.run(udp_open_,[&]{return p.a->udp_open({p.ac.local_addr,4000});}).value();
    p.server=win.run(udp_open_,[&]{return p.b->udp_open(p.peer);}).value();
  }
  std::array<std::byte,32768> payload;
  for (unsigned round=0;round<289;++round) {
    win.phase=round==0 ? first : round<=32 ? warm : round<=160 ? steady_a : steady_b;
    p.advance(p.now+100us);
    // At each fixed epoch, revisit the larger high-water mark every eight rounds.
    auto n=is_ip ? 257u : (mode=="echo" || mode=="timer_loss" || mode=="delack") ? 64u : round%8 ? 16384u : 32768u;
    for (unsigned i=0;i<n;++i) payload[i]=std::byte((i*13 + (i>>7) + round*31) & 255);
    auto data=std::span(payload).first(n);
    if (is_ip) p.ip(round,data);
    else if (mode=="multi_waiter") p.multi_waiter(data);
    else {
      if (mode=="timer_loss" && round%8==0) p.timer_drops=2;
      p.inject=(round%8==0 && (mode=="reorder" || mode=="loss" || mode=="duplicate")) || (round%32==0 && mode=="pmtu");
      p.transfer(*p.a,p.client,*p.b,p.server,data);
      if (mode=="pmtu" && round%32==0) {
        p.advance(p.now+3s);
        require(p.a->debug_usage().stack_timers_armed==0,"expired PMTU");
        ++p.expired;
      }
      if (mode=="echo") p.transfer(*p.b,p.server,*p.a,p.client,data);
    }
  }
  if (mode=="pmtu") {
    require(p.pmtu_count==10 && p.expired==10,"ten PMTU applications and expiries");
    p.advance(p.now+3s);
    require(p.a->debug_usage().stack_timers_armed==0,"PMTU cache expiry");
  }
  if (mode=="duplicate") require(p.duplicate_count==37,"duplicated ordinary datagrams");
  if (mode=="reorder") require(p.reorders>0,"reorder path");
  if (mode=="loss") {
    auto info=p.a->tcp_info(p.client).value();
    require(p.losses>0 && info.total_retrans>0,"retransmission path");
  }
  if (mode=="timer_loss") {
    require(p.losses==74 && p.timer_wakes>=74 && p.a->tcp_info(p.client)->total_retrans>=74,"ordinary timer recovery");
    if (trace) require(p.sink.fired_rto>0,"RTO fired in trace");
  }
  if (mode=="delack") {
    require(p.timer_wakes>0,"delayed-ACK deadline reached");
    if (trace) require(p.sink.fired_delack>0,"delayed ACK fired in trace");
  }
  if (mode=="pool_pressure") require(p.blocked>0,"packet pool exhaustion");
  if (mode=="tx_pressure") require(p.blocked>0,"TX queue pressure");
  if (mode=="chunk_pressure") require(p.would_block>0,"chunk waiter pressure");
  if (mode=="gso" || mode=="fallback") require(p.gso>0,"GSO path");
  if (mode=="fallback") require(p.full_packets_after_gso>0,"full MSS packets queued with the sole GSO buffer in use");
  auto trace_count=std::uint64_t{};
  for (unsigned i=0;i<p.sink.kinds.size();++i) {
    trace_count+=p.sink.kinds[i];
    if (p.sink.kinds[i]) std::fprintf(stderr,"trace,%u,%llu\n",i,(unsigned long long)p.sink.kinds[i]);
  }
  if (!is_ip) require(trace==(trace_count>0),"trace dispatch");
  win.phase=shutdown_;
  if (!is_ip) {
    win.run(close_,[&]{return p.a->tcp_close(p.client);}); p.pump();
    win.run(close_,[&]{return p.b->tcp_close(p.server);}); p.pump();
    win.run(close_,[&]{return p.b->tcp_close(p.listener);});
  } else if (mode=="udp") {
    win.run(close_,[&]{return p.a->udp_close(p.client);});
    win.run(close_,[&]{return p.b->udp_close(p.server);});
  }
  p.a->debug_check();p.b->debug_check();
  require(std::fclose(wire_file)==0 && std::fclose(event_file)==0 && std::fclose(tx_file)==0,"transcript close");
  win.print();
  std::fprintf(stderr,"coverage,gso=%llu,ordinary=%llu,tx_blocked=%llu,chunk_blocked=%llu,reordered=%llu,dropped=%llu,timer_wakes=%llu\n",
      (unsigned long long)p.gso,(unsigned long long)p.ordinary,(unsigned long long)p.blocked,
      (unsigned long long)p.would_block,(unsigned long long)p.reorders,(unsigned long long)p.losses,(unsigned long long)p.timer_wakes);
  std::fprintf(stderr,"coverage,duplicates=%u,pmtu=%u,expiry=%u,waiters_last=%u,full_mss_after_gso=%u\n",
      p.duplicate_count,p.pmtu_count,p.expired,p.wake_count,p.full_packets_after_gso);
  std::fprintf(stderr,"coverage,trace_rto_fired=%u,trace_delack_fired=%u\n",p.sink.fired_rto,p.sink.fired_delack);
  require(utcp_heap_write_sites(stderr),"call-site recorder capacity");
}
