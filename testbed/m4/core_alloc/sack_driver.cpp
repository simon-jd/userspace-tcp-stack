#include "windows.hpp"
#include "core/tcp/send_queue.hpp"
#include "core/tcp/rack.hpp"

#include <algorithm>
#include <array>
#include <cstring>

using namespace utcp;
int main(int argc,char**) {
  Windows win;
  utcp_heap_sites(argc>1);
  constexpr unsigned length=6400, mss=100;
  ChunkPool pool(4);
  SendQueue q(pool,length);
  std::array<std::byte,length> payload{};
  SentFifo fifo;
  for (unsigned epoch=0;epoch<289;++epoch) {
    win.phase=!epoch ? first : epoch<=32 ? warm : epoch<=160 ? steady_a : steady_b;
    const auto base=q.end();
    std::array<bool,length> bitmap{};
    require(win.run(send_,[&]{return q.write(payload);})==length,"queued payload");
    win.row(send_).bytes+=length;
    for (unsigned i=0;i<length;i+=mss) {
      win.run(pop_,[&]{
        const auto& s=q.on_transmit(base+i,mss,false,Time{(std::int64_t)epoch},{});
        fifo.on_transmit(q,s);
      });
      ++win.row(pop_).segments;win.row(pop_).bytes+=mss;
    }
    auto apply=[&](unsigned lo,unsigned hi,Path p) {
      std::array<Range,1> b{Range{base+lo,base+hi}};
      win.run(p,[&]{q.on_sack(b,{},[](const auto&,bool){});});
      std::fill(bitmap.begin()+lo,bitmap.begin()+hi,true);
      auto expected=std::count(bitmap.begin(),bitmap.end(),false);
      require(q.in_flight_bytes()==expected,"byte bitmap");
      win.row(p).bytes+=hi-lo;
    };
    for (unsigned j=0;j<8;++j) {
      const auto lo=353+300*j;
      for (unsigned hi=lo+1;hi<=lo+67;hi+=11) {
        apply(lo,hi,partial_);apply(lo,hi,repeat_);
      }
    }
    apply(353,2600,partial_);
    // A normal path-MTU reduction divides live TxSegs. Rebuild RACK order and
    // check stable, nondecreasing offsets for equal transmission timestamps.
    win.run(pmtu_,[&]{q.split_to_mss(63);fifo.rebuild(q);});
    auto offsets=fifo.live_offsets(q);
    require(std::is_sorted(offsets.begin(),offsets.end()),"RACK PMTU order");
    win.run(sack_drain_,[&]{q.on_cumulative_ack(base+length,{},[](const auto&,bool){});
      fifo.walk(q,[](const TxSeg&){return true;});});
    win.row(sack_drain_).bytes+=length;
    require(!q.in_flight_bytes() && !q.counters().packets_out && !fifo.size(),"full queue drain");
  }
  win.print();require(utcp_heap_write_sites(stderr),"site capacity");
}
