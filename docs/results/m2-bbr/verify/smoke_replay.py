"""Rebuild the BBR smoke evidence from endpoint records and the fixed plan."""
import collections
import csv
import json
import statistics
import sys
from pathlib import Path

repo, camp, out, freeze = map(Path, sys.argv[1:])
sys.path[:0] = [str(repo/'tools/m2'), str(repo/'docs/results/m2-checkpoint/verify')]
import analyze as a
import matrix as m
import checkpoint_inputs as c
import verify_endpoint_cc as endpoint
import verify_profile_trace as profile

out.mkdir(exist_ok=False)
frozen = c.load(freeze)
registered = m.expand_plan(m.load_plan(repo/'docs/results/m2-bbr/plan.toml'), 1)
assert c.load(camp/'plan.json')['runs'] == registered
plans = {row['run']: row for row in registered}
members = []
for path in sorted(camp.glob('*/meta.json')):
    meta, summ = c.load(path), c.load(path.parent/'summary.json')
    planned = plans[meta.get('rerun_of', meta['run'])]
    for field in ('cell','algo','cc','impl','duration','group','in_group','order','rep','rtt','bw','loss','queue_bdp','seed','plan_seed'):
        assert meta[field] == planned[field], (path,field)
    assert all(meta[k]==v for k,v in frozen['static'].items())
    assert meta['slot'] == 0 and meta['cpusets']==frozen['slots']['0']['cpus']
    assert meta['reuse_key']==frozen['slots']['0']['reuse_key']
    assert meta['cc']=='bbr' and meta['gate'].endswith('-s0')
    members.append((meta,summ))
pairs, bad, status = c.independently_count(members)
assert status=='ok' and len(pairs)==5 and len({pair[0][0]['rep'] for pair in pairs})==5
counted = {meta['run'] for pair in pairs for meta,summ in pair}
rows = [c.details(camp/meta['run'],meta,summ,meta['run'] in counted,a,m) for meta,summ in members]
c.write_csv(out/'evidence.csv',c.ROWS,rows)
endpoint.main(camp,out/'evidence.csv',out/'endpoint-cc.csv')
trace_results = {}
reference = c.load(repo/'docs/results/m2-checkpoint/verify/linux-profile.json')
for meta,summ in members:
    name = meta['run']
    if name not in counted or meta['impl']!='utcp':
        continue
    rd=camp/name
    stream = [json.loads(line) for line in (rd/'snd.jsonl').read_text().splitlines()]
    config, = [row for row in stream if row.get('ev')=='config']
    assert meta['profile']=='linux' and config==reference and meta['stack_set']==profile.BASE_SETS and not meta.get('stack_args')
    ids = {row['conn_id'] for row in stream if row.get('ev')=='sample'}
    conn, = ids
    stats = c.load(rd/'stats.json')
    counts,digest=profile.check_trace(rd/'trace.jsonl',meta,conn,stats['trace_events'])
    values = {key:[] for key in ('bbr_bandwidth_q24','bbr_min_rtt_us','bbr_cwnd_gain_q8','bbr_pacing_gain_q8')}
    modes, lt, transitions=collections.Counter(), collections.Counter(), []
    for line in (rd/'trace.jsonl').open():
        event=json.loads(line)
        if 'bbr_mode' not in event: continue
        mode=event['bbr_mode']
        assert mode in ('STARTUP','DRAIN','PROBE_BW','PROBE_RTT')
        modes[mode]+=1
        lt[str(event['bbr_lt_use_bw'])]+=1
        for k,nums in values.items(): nums.append(event[k])
        if not transitions or transitions[-1][1]!=mode: transitions.append([event['t'],mode])
    assert sum(modes.values())>0 and max(values['bbr_bandwidth_q24'])>0
    trace_results[name]={'modes':modes,'lt_use_bw':lt,'mode_transitions':transitions,'fields':{k:[min(v),max(v)] for k,v in values.items()},'stats_trace_events':stats['trace_events'],'counts':counts,'sha256':digest,'profile_fields':len(config),'config':config}
(out/'bbr-trace.json').write_text(json.dumps(trace_results,indent=2,sort_keys=True)+'\n')
medians = {}
for impl in ('utcp','linux'):
    by_rate = sorted((summ['goodput_bps'],meta['run']) for pair in pairs for meta,summ in pair if meta['impl']==impl)
    medians[impl]=by_rate[2][1]
(out/'medians.json').write_text(json.dumps(medians,sort_keys=True)+'\n')
print('counted_pairs',len(pairs),'excluded',bad,'actual_median_runs',medians)
