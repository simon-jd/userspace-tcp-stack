"""Check the maximum-value width of real production JSONL schemas with the allocation oracle."""
import json
from pathlib import Path
import re
import subprocess
import sys

root=Path(__file__).resolve().parents[3]
rows=json.loads(Path(sys.argv[1]).read_text())
out=Path(sys.argv[2])
out.mkdir(parents=True,exist_ok=True)
bound=re.search(r'max_load_line = (2 \+ 26 \* \(19 \+ 4 \+ 20\));',(root/"apps/utcp-echo/echo.cpp").read_text())
assert bound
code=['#include "common/jsonl.hpp"','#include <cstdint>','#include <cstdio>','#include <dlfcn.h>',
    'int main(){auto read=reinterpret_cast<void(*)(uint64_t*,uint64_t*)>(dlsym(RTLD_DEFAULT,"utcp_counter_read")); if(!read)return 2;']
for row in rows:
    assert len(row)<=26 and max(map(len,row))<=19
    role=row["role"]
    code+=['{utcp::app::JsonLine line; line.reserve('+bound[1]+'); uint64_t a,b,c,d; read(&a,&b);']
    for k,v in row.items():
        value='UINT64_MAX' if type(v)==int else json.dumps("baseline" if k=="phase" else v)
        code.append('line.add('+json.dumps(k)+','+value+');')
    code+=['read(&c,&d); auto size=line.str().size(); printf("'+role+' bytes=%zu allocations=%llu requested=%llu\\n",size,(unsigned long long)(c-a),(unsigned long long)(d-b)); if(a!=c || b!=d) return 1; }']
code+=['}']
(out/"width.cpp").write_text("\n".join(code))
b=root/"build/gcc-release"
subprocess.run(["g++-15","-std=c++23","-O3","-I"+str(root/"include"),"-I"+str(root/"apps"),str(out/"width.cpp"),
    str(b/"apps/common/libutcp_appkit.a"),"-ldl","-o",str(out/"check")],check=True)
