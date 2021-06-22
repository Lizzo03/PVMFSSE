# RocksDB 5.18.4

> document：https://github.com/facebook/rocksdb/blob/257b458121b7c684f432838ca0e45c1500744c89/INSTALL.md
>
> platform：ubuntu desktop 18.04

Upgrade your gcc to version at least 4.8 to get C++11 support.

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install gcc-4.8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 50
apt-get install g++-4.8
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 50
gcc --version
g++ --version
```

we can get gcc7.3 and g++7.3 directly in following way

```bash
sudo apt-get install build-essential autoconf libtool pkg-config
```

Install gflags. First, try: sudo apt-get install libgflags-dev If this doesn't work and you're using Ubuntu, here's a nice tutorial: (http://askubuntu.com/questions/312173/installing-gflags-12-04)

```bash
sudo apt-get install libgflags-dev
```

Install snappy. This is usually as easy as: sudo apt-get install libsnappy-dev.

```bash
sudo apt-get install -y libsnappy-dev
```

Install zlib. Try: sudo apt-get install zlib1g-dev.

```bash
sudo apt-get install -y zlib1g-dev
```

Install bzip2: sudo apt-get install libbz2-dev.

```bash
sudo apt-get install -y libbz2-dev
```

Install lz4: sudo apt-get install liblz4-dev.

```bash
sudo apt-get install -y liblz4-dev
```

Install zstandard: sudo apt-get install libzstd-dev.

```bash
sudo apt-get install -y libzstd-dev
```

```bash
# RocksDB
git clone -b 5.18.fb https://github.com/facebook/rocksdb.git
cd rocksdb
# get librocksdb.so
make shared_lib
cp -r ./include/rocksdb /usr/include
cp librocksdb.so.5.18.0 /usr/lib
ln -s /usr/lib/librocksdb.so.5.18.0 /usr/lib/librocksdb.so.5
ln -s /usr/lib/librocksdb.so.5.18.0 /usr/lib/librocksdb.so	
```



# cryptopp

```bash
git clone https://github.com/weidai11/cryptopp.git
cd cryptopp
make
make test
make install
```



# grpc 1.17

> document：https://github.com/grpc/grpc/blob/master/BUILDING.md
> platform：ubuntu desktop 18.04


#### install build essential

```bash
sudo apt-get install build-essential autoconf libtool pkg-config
```

####  compile

```bash
git clone -b v1.17.0 https://github.com/grpc/grpc
cd grpc
git submodule update --init
```

if there are any errors, then

```bash
# vi .gitmodules
```

```txt
[submodule "third_party/gflags"]
	    path = third_party/gflags
	    url = https://github.com/tangmi360/gflags.git
```

```bash
# make
# make install
```

#### install protobuf 3.6.1

```bash
# cd third_party/protobuf
# make && sudo make install
```

#### Set environment

make sure where `pkgconfig` is on your computer, mine is `usr/local/lib/pkgconfig`

```bash
# export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

set the path of library, otherwise we cannot find where `libgrpc++.so.1` is


```bash
# vi /etc/ld.so.conf.d/grpc.conf
# add "/usr/local/lib"
# ldconfig
```

#### run the example project

```bash
cd grpc/examples/cpp/helloworld
make
./greeter_server
./greeter_client
```



# PBC 0.5.14

#### 依赖预安装

```
$ sudo apt-get install m4 
$ sudo apt-getinstall g++ 
$ sudo apt-getinstall flex
```

#### 安装GMP

[GMP官网](https://gmplib.org/)下载包（如`gmp-6.1.2.tar.lz`）并解压。

```
$ cd gmp 
$ ./configure
$ make 
$ make check 
$ sudo make install
```

**Tip:**系统下可能有`configure`脚本无法执行的问题，使用chmod命令赋予权限：

```
$ sudo chmod +x ./configure
```

#### 安装PBC

```
$ cd pbc 
$ ./configure 
$ make 
$ make install
```

#### 管理库路径

添加pbc库文件`libpbc.so.1`路径。

```
$ cd /etc/ld.so.conf.d 
$ sudo vi libpbc.conf
```

在`/etc/ld.so.conf.d`路径下新建`libpbc.conf`文件，内容为：

```
/usr/local/lib
```

更新cache:

```
$ sudo ldconfig
```

