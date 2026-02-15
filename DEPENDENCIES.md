## Boost Build
```
$ git clone --branch boost-1.90.0 --depth 1 https://github.com/boostorg/boost.git
$ cd boost/
$ git submodule update --init --recursive
$ ./bootstrap.sh --prefix="/home/timothybanks/sandbox/usr/local"
$ ./b2 -j"$(nproc)" install
```
## gRPC Build
```
$ git clone --depth 1 --branch v1.78.0 https://github.com/grpc/grpc.git
$ git submodule update --init --recursive
```
### GoogleTest Build
```
$ cd third_party/googletest
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_GMOCK=ON \
    ..
$ make install -j8
```
### Abseil Build
```
$ cd third_party/abseil-cpp
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DABSL_BUILD_TESTING=OFF \
    -DABSL_USE_GOOGLETEST_HEAD=OFF \
    -DABSL_USE_EXTERNAL_GOOGLETEST=ON \
    -DABSL_FIND_GOOGLETEST=ON \
    -DABSL_ENABLE_INSTALL=ON \
    ..
$ make intsall -j8
```
### Protobuf Build
```
$ cd third_party/protobuf
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DABSL_PROPAGATE_CXX_STD=ON \
    -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_SHARED_LIBS=ON \
    -Dprotobuf_BUILD_LIBUPB=ON \
    -Dprotobuf_ABSL_PROVIDER=package \
    ..
$ make install -j8    
```
### gRPC continued
```
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_RPATH=/home/timothybanks/sandbox/usr/local/lib \
    -DCMAKE_BUILD_RPATH="@loader_path/../lib" \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=OFF \
    -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
    -DgRPC_INSTALL=ON \
    -DgRPC_BUILD_TESTS=OFF \
    -DgRPC_ABSL_PROVIDER=package \
    -DgRPC_PROTOBUF_PROVIDER=package \
    -DBUILD_SHARED_LIBS=ON \
    -DABSL_PROPAGATE_CXX_STD=ON \
    ..
$ make install -j8
```
## llvm/clang build
```
$ git clone --depth 1 --branch llvmorg-21.1.8 https://github.com/llvm/llvm-project.git
$ cd llvm-project
$ git submodule update --init --recursive
$ cd llvm
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lldb;lld" \
    -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi;libunwind" \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    ..
$ make install -j8    
```
## spdlog build
```
$ git clone --depth 1 --branch v1.15.0 https://github.com/gabime/spdlog.git
$ cd spdlog
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DSPDLOG_USE_STD_FORMAT=ON \
    ..
$ make install -j8
```
## SCALE codec
```
$ git clone --depth 1 --branch v2.0.2 https://github.com/qdrvm/scale-codec-cpp.git
$ cd scale-codec-cpp
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    ..
$ make install -j8
```
## gflags
```
$ git clone --depth 1 --branch v2.3.0 https://github.com/gflags/gflags.git
$ cd gflags
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    ..
$ make install -j8
```
## Rocksdb
```
$ git clone --depth 1 --branch v10.10.1 https://github.com/facebook/rocksdb.git
$ cd rocksdb
$ mkdir build
$ cd build
$ cmake \
    -DCMAKE_INSTALL_PREFIX=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_PREFIX_PATH=/home/timothybanks/sandbox/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DWITH_TESTS=OFF \
    -DWITH_BENCHMARK_TOOLS=OFF \
    -DWITH_ALL_TESTS=OFF  \
    ..
$ make install -j8
```