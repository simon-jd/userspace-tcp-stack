# Build and testbed image: compilers, the unit test framework and the network
# tools for the testbed (nftables and conntrack for the DUT's NAT,
# testbed/m1/nat.sh). Build with testbed/build-image.sh (tag utcp-testbed:dev).
#
# The base image is pinned by its index digest. GoogleTest is pinned by
# package version because the tests are written against it; the rest comes
# from the 26.04 archive at build time and every installed version is listed
# in /usr/share/utcp-testbed/packages.txt (see docs/ENVIRONMENT.md).
FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-15 g++-15 \
      clang-21 libclang-rt-21-dev llvm-21 \
      cmake ninja-build \
      googletest=1.17.0-1build1 \
      iperf3 tcpdump tshark nginx \
      iproute2 ethtool iputils-ping curl netcat-openbsd procps nftables conntrack \
      python3 python3-numpy python3-matplotlib \
      ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /usr/share/utcp-testbed \
 && dpkg-query -W -f '${Package}\t${Version}\n' | sort > /usr/share/utcp-testbed/packages.txt

# Symbolized ASan/UBSan reports for clang builds (GCC's runtime symbolizes by itself).
ENV ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-21/bin/llvm-symbolizer

CMD ["bash"]
