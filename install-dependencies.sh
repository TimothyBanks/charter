#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# build_deps.sh
#
# Parameters:
#   --install-prefix PATH   Where "make install" installs into
#   --prefix-path    PATH   What CMake uses to find dependencies (CMAKE_PREFIX_PATH)
#   -j, --jobs       N      Parallelism (default: nproc)
#   --workdir        PATH   Where repos/build dirs live (default: cwd)
#
# Defaults are your current values.
# ------------------------------------------------------------------------------

INSTALL_PREFIX_DEFAULT="/home/timothybanks/sandbox/usr/local"
PREFIX_PATH_DEFAULT="/home/timothybanks/sandbox/usr/local"

INSTALL_PREFIX="$INSTALL_PREFIX_DEFAULT"
PREFIX_PATH="$PREFIX_PATH_DEFAULT"
JOBS="$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu || echo 8)"
WORKDIR="$(pwd)"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --install-prefix PATH   Install prefix (default: $INSTALL_PREFIX_DEFAULT)
  --prefix-path PATH      Prefix path for dependency discovery (default: $PREFIX_PATH_DEFAULT)
  -j, --jobs N            Parallel jobs (default: $JOBS)
  --workdir PATH          Working directory for clones/builds (default: current directory)
  -h, --help              Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-prefix) INSTALL_PREFIX="$2"; shift 2 ;;
    --prefix-path)    PREFIX_PATH="$2"; shift 2 ;;
    -j|--jobs)        JOBS="$2"; shift 2 ;;
    --workdir)        WORKDIR="$2"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

mkdir -p "$WORKDIR"
cd "$WORKDIR"

log() { printf "\n\033[1m==> %s\033[0m\n" "$*"; }

cmake_configure_build_install() {
  local src_dir="$1"
  local build_dir="$2"
  shift 2
  mkdir -p "$build_dir"
  cmake -S "$src_dir" -B "$build_dir" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    "$@"
  cmake --build "$build_dir" -j"$JOBS"
  cmake --install "$build_dir"
}

git_clone_if_missing() {
  local dir="$1"; shift
  if [[ -d "$dir/.git" ]]; then
    log "$dir already exists; skipping clone"
  else
    log "Cloning $dir"
    git clone "$@" "$dir"
  fi
}

# ------------------------------------------------------------------------------
# Boost
# ------------------------------------------------------------------------------
log "Boost 1.90.0"
git_clone_if_missing boost --branch boost-1.90.0 --depth 1 https://github.com/boostorg/boost.git
pushd boost >/dev/null
git submodule update --init --recursive
./bootstrap.sh --prefix="$INSTALL_PREFIX"
./b2 -j"$JOBS" install
popd >/dev/null

# ------------------------------------------------------------------------------
# gRPC (and its third_party deps that you’re building manually)
# ------------------------------------------------------------------------------
log "gRPC v1.78.0"
git_clone_if_missing grpc --depth 1 --branch v1.78.0 https://github.com/grpc/grpc.git
pushd grpc >/dev/null
git submodule update --init --recursive

log "GoogleTest (from grpc/third_party/googletest)"
cmake_configure_build_install third_party/googletest third_party/googletest/build \
  -DBUILD_SHARED_LIBS=ON \
  -DBUILD_GMOCK=ON

log "Abseil (from grpc/third_party/abseil-cpp)"
cmake_configure_build_install third_party/abseil-cpp third_party/abseil-cpp/build \
  -DABSL_BUILD_TESTING=OFF \
  -DABSL_USE_GOOGLETEST_HEAD=OFF \
  -DABSL_USE_EXTERNAL_GOOGLETEST=ON \
  -DABSL_FIND_GOOGLETEST=ON \
  -DABSL_ENABLE_INSTALL=ON

log "Protobuf (from grpc/third_party/protobuf)"
cmake_configure_build_install third_party/protobuf third_party/protobuf/build \
  -DABSL_PROPAGATE_CXX_STD=ON \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_SHARED_LIBS=ON \
  -Dprotobuf_BUILD_LIBUPB=ON \
  -Dprotobuf_ABSL_PROVIDER=package

log "gRPC (build+install)"
mkdir -p build
cmake -S . -B build \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_INSTALL_RPATH="$INSTALL_PREFIX/lib" \
  -DCMAKE_BUILD_RPATH="@loader_path/../lib" \
  -DCMAKE_BUILD_WITH_INSTALL_RPATH=OFF \
  -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
  -DgRPC_INSTALL=ON \
  -DgRPC_BUILD_TESTS=OFF \
  -DgRPC_ABSL_PROVIDER=package \
  -DgRPC_PROTOBUF_PROVIDER=package \
  -DBUILD_SHARED_LIBS=ON \
  -DABSL_PROPAGATE_CXX_STD=ON
cmake --build build -j"$JOBS"
cmake --install build
popd >/dev/null

# ------------------------------------------------------------------------------
# llvm/clang
# Note: Your original snippet didn’t set an install prefix; this script installs
#       LLVM into INSTALL_PREFIX for consistency.
# ------------------------------------------------------------------------------
log "LLVM/Clang llvmorg-21.1.8"
git_clone_if_missing llvm-project --depth 1 --branch llvmorg-21.1.8 https://github.com/llvm/llvm-project.git
pushd llvm-project >/dev/null
git submodule update --init --recursive
cmake -S llvm -B llvm/build \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lldb;lld" \
  -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi;libunwind" \
  -DLLVM_TARGETS_TO_BUILD="X86"
cmake --build llvm/build -j"$JOBS"
cmake --install llvm/build
popd >/dev/null

# ------------------------------------------------------------------------------
# spdlog
# ------------------------------------------------------------------------------
log "spdlog v1.15.0"
git_clone_if_missing spdlog --depth 1 --branch v1.15.0 https://github.com/gabime/spdlog.git
cmake_configure_build_install spdlog spdlog/build \
  -DSPDLOG_USE_STD_FORMAT=ON

# ------------------------------------------------------------------------------
# SCALE codec + qtils
# Note: qtils is a dependency; it’s often safer to build qtils first.
# ------------------------------------------------------------------------------
log "qtils v0.1.6"
git_clone_if_missing qtils --depth 1 --branch v0.1.6 https://github.com/qdrvm/qtils.git
cmake_configure_build_install qtils qtils/build

log "scale-codec-cpp v2.0.2"
git_clone_if_missing scale-codec-cpp --depth 1 --branch v2.0.2 https://github.com/qdrvm/scale-codec-cpp.git
cmake_configure_build_install scale-codec-cpp scale-codec-cpp/build

# ------------------------------------------------------------------------------
# fmt
# ------------------------------------------------------------------------------
log "fmt 12.1.0"
git_clone_if_missing fmt --depth 1 --branch 12.1.0 https://github.com/fmtlib/fmt.git
cmake_configure_build_install fmt fmt/build \
  -DFMT_TEST=OFF

# ------------------------------------------------------------------------------
# gflags
# ------------------------------------------------------------------------------
log "gflags v2.3.0"
git_clone_if_missing gflags --depth 1 --branch v2.3.0 https://github.com/gflags/gflags.git
cmake_configure_build_install gflags gflags/build

# ------------------------------------------------------------------------------
# RocksDB
# ------------------------------------------------------------------------------
log "RocksDB v10.10.1"
git_clone_if_missing rocksdb --depth 1 --branch v10.10.1 https://github.com/facebook/rocksdb.git
cmake_configure_build_install rocksdb rocksdb/build \
  -DWITH_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_ALL_TESTS=OFF

# ------------------------------------------------------------------------------
# blake3 (C implementation)
# ------------------------------------------------------------------------------
log "BLAKE3 1.8.3 (c/)"
git_clone_if_missing BLAKE3 --depth 1 --branch 1.8.3 https://github.com/BLAKE3-team/BLAKE3.git
cmake_configure_build_install BLAKE3/c BLAKE3/c/build

# ------------------------------------------------------------------------------
# libsodium (Autotools)
# ------------------------------------------------------------------------------
log "libsodium 1.0.21-RELEASE"
git_clone_if_missing libsodium --depth 1 --branch 1.0.21-RELEASE https://github.com/jedisct1/libsodium.git
pushd libsodium >/dev/null
./configure --prefix="$INSTALL_PREFIX"
make -j"$JOBS"
make install
popd >/dev/null

# ------------------------------------------------------------------------------
# libsecp256k1
# ------------------------------------------------------------------------------
log "secp256k1 v0.7.1"
git_clone_if_missing secp256k1 --depth 1 --branch v0.7.1 https://github.com/bitcoin-core/secp256k1.git
cmake_configure_build_install secp256k1 secp256k1/build \
  -DSECP256K1_BUILD_BENCHMARK=OFF \
  -DSECP256K1_BUILD_TESTS=OFF \
  -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
  -DSECP256K1_BUILD_CTIME_TESTS=OFF

# ------------------------------------------------------------------------------
# blst (custom build.sh + manual install)
# ------------------------------------------------------------------------------
log "blst v0.3.16"
git_clone_if_missing blst --depth 1 --branch v0.3.16 https://github.com/supranational/blst.git
pushd blst >/dev/null
mkdir -p build
pushd build >/dev/null
../build.sh
install -d "$INSTALL_PREFIX/lib" "$INSTALL_PREFIX/include"
install -m 644 libblst.a "$INSTALL_PREFIX/lib/"
install -m 644 ../bindings/blst.h "$INSTALL_PREFIX/include/"
install -m 644 ../bindings/blst_aux.h "$INSTALL_PREFIX/include/"
install -m 644 ../bindings/blst.hpp "$INSTALL_PREFIX/include/"
popd >/dev/null
popd >/dev/null

# ------------------------------------------------------------------------------
# zstd
# ------------------------------------------------------------------------------
log "zstd"
git_clone_if_missing zstd --depth 1 https://github.com/facebook/zstd.git
cmake_configure_build_install zstd zstd/build.release

# ------------------------------------------------------------------------------
# simdjson
# ------------------------------------------------------------------------------
log "simdjson v4.2.4"
git_clone_if_missing simdjson --depth 1 --branch v4.2.4 https://github.com/simdjson/simdjson.git
cmake_configure_build_install simdjson simdjson/build

log "All done."
echo "Installed into: $INSTALL_PREFIX"
echo "CMAKE_PREFIX_PATH used: $PREFIX_PATH"
