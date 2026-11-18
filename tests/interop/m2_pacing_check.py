"""Run the benchmark entry point against deterministic Docker and bulk output."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

# Replace only the external testbed. The shell entry point still configures
# the path, inspects it, runs both endpoints, and decides the process status.
LIB = r'''
set +e
tb_dut=dut tb_peer=peer tb_dut_ip=1 tb_peer_ip=2 tb_tun=utcp0 tb_image=test
m1_bin=/bin m1_repo=. m1_prefix=test m1_volume=test m1_voldir=test
m1_need_programs() { :; }
m1_testbed_up() { touch "$M1_RESULTS/up"; }
m1_pmtu() { :; }
m1_netem() { :; }
m1_log() { :; }
m1_wait_kernel_listen() { :; }
m1_case_dir() { mkdir -p "$M1_RESULTS/$1"; }
tb_die() { echo "$*" >&2; exit 1; }
tb_ifname() { echo eth0; }
tb_sh() { [[ $SETUP != error ]]; }
tb_exec() {
  local ctr=$1
  shift
  case "$1" in
    ip) echo '[{"gso_ipv4_max_size":65536}]';;
    tc)
      if [[ "$*" == *utcp0* && $SETUP == wrong-delay ]]; then
        echo 'qdisc netem 3030: root refcnt 2 limit 20000 delay 9ms'
      else
        echo 'qdisc netem 3030: root refcnt 2 limit 20000 delay 10ms'
      fi;;
    timeout) touch "$M1_RESULTS/started"; cat "$M1_RESULTS/$ctr.json";;
    cat) [[ "$*" == *utcp-stats* ]] && echo '{}';;
    rm) :;;
  esac
}
docker() {
  if [[ $1 == inspect || $2 == inspect && $1 == container ]]; then
    if [[ ${!#} == peer && $SETUP == wrong-cpu ]]; then echo 8-11
    else echo 12,13,14,15; fi
  elif [[ $1 == run ]]; then
    python3 -I -c "$replay_py"
  fi
}
date() { if [[ $1 == +%s.%N ]]; then echo 100.0; else command date -u; fi; }
'''

class Benchmark(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.script = self.root / 'm2_pacing.sh'
        shutil.copy(HERE / self.script.name, self.script)
        (self.root / 'm1_lib.sh').write_text(LIB)
        self.summary = dict(ev='summary', ok=True, sha256='a' * 64, bytes=125000000,
                            duration_us=20000000, goodput_bps=50000000, lateness_count=20,
                            lateness_p50_ns=1000, lateness_p99_ns=4000,
                            lateness_p999_ns=8000, lateness_max_ns=6000)

    def bench(self, args=('--no-trace',), setup='ok', sender=None, receiver=None):
        for role, record in [('dut', sender), ('peer', receiver)]:
            (self.root / (role + '.json')).write_text(
                json.dumps(self.summary if record is None else record, separators=(',', ':')) + '\n')
        return subprocess.run(['bash', str(self.script), '--cpus', '12-15', *args],
                              env=dict(os.environ, M1_RESULTS=str(self.root), SETUP=setup,
                                       UTCP_COMMIT='test'), capture_output=True, timeout=3 if args == ('--runs',) else 20)

    def test_valid_measurement_and_observed_affinities(self):
        result = self.bench()
        self.assertEqual(result.returncode, 0, result.stderr)
        setup = (self.root / 'pacing-1/setup.txt').read_text()
        self.assertIn('dut_cpuset 12,13,14,15', setup)
        self.assertIn('peer_cpuset 12,13,14,15', setup)

    def test_short_transfer(self):
        self.summary.update(duration_us=1000000, bytes=6250000)
        self.assertNotEqual(self.bench().returncode, 0)

    def test_incomplete_evidence(self):
        for changes in [dict(lateness_count=0), dict(lateness_p99_ns=None), dict(ok=False),
                        dict(sha256=''), dict(bytes=1)]:
            with self.subTest(changes=changes):
                self.assertNotEqual(self.bench(sender=dict(self.summary, **changes)).returncode, 0)

    def test_missing_both_digests(self):
        del self.summary['sha256']
        self.assertNotEqual(self.bench().returncode, 0)

    def test_empty_requested_trace(self):
        self.assertNotEqual(self.bench(args=()).returncode, 0)

    def test_preflight_aborts_before_transfer(self):
        for setup in ['wrong-cpu', 'error', 'wrong-delay']:
            with self.subTest(setup=setup):
                self.assertNotEqual(self.bench(setup=setup).returncode, 0)
                self.assertFalse((self.root / 'started').exists())

    def test_invalid_run_count(self):
        for args in [('--runs', '0'), ('--runs',)]:
            with self.subTest(args=args):
                self.assertEqual(self.bench(args).returncode, 2)
                self.assertFalse((self.root / 'up').exists())


if __name__ == '__main__':
    unittest.main()
