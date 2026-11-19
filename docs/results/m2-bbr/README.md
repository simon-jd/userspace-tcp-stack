# BBRv1 measurement inputs

The release candidate is `769311e157dea0e7983a2cd5bd086736339dc62b`. Two independent builds used the clean tracked source, the testbed image and the same in-container source path, `/home/postedism/Desktop/utcp-wt/int-wire40`. They produced identical `utcp-bulk` and `libutcp_core.a` files. On the private Ubuntu host, run the following from the later measurement checkout to restore the measured pair. The recipe checks existing files before using them and validates the preset, kernel, image and timing scripts.

```sh
taskset -c 16-31 nice -n 10 bash docs/results/m2-bbr/restore-runtime.sh \
    3dcd4b48508c8d3352157460bf1f819c472741d40dd095d74dfd8eb245bb4eac
```

The source archive, source manifest, build logs, exact CMake configuration, both binaries, restore script and preregistered pair order are under `utcp-data:/m2/archive/m2c-bbr-769311e-runtime-a1/`. The volume retains the original file bytes and SHA-256 manifest. The runtime uses kernel `7.0.0-42-generic`, `gcc-release` and image `sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`.

| Input | SHA-256 |
|---|---|
| utcp-bulk | `6bf415a2a5745d356e4583d633327bc3d58f7b49a4ae2c47078fb54405acbc7d` |
| libutcp_core.a | `c3d0fa75effdfc6215e5eb80db0e96cb196ccf79c4c3bffc0b2bce54e2e35d53` |
| tools/m2 and testbed/m2 | `43bf359c7ba1bf5d40f3a58ef7c4c9e5ba82737038b6d25ba35aa52d55b72912` |
| plan.toml | `2b82eec750eb826956239fccb6cb2c3bcf1f9311ddd24a098900b151221fbdf1` |
| pair-order.txt | `d5d8203e4fe494859c8561d79cb70b8d2d308ffa898a42d95666d66ef0fdb29e` |

The smoke plan has one cell at 100 Mbit/s, 20 ms, 0% configured random loss and two BDPs of queue. Each of five repetitions places BBR on the stack and on Linux in consecutive 30-second transfers on slot 0. The launch order comes from seed `2026111903`. To recheck the ten registered specifications, run the following in the measured checkout.

```sh
python3 -B tools/m2/matrix.py expand docs/results/m2-bbr/plan.toml | cmp - docs/results/m2-bbr/pair-order.txt
```
