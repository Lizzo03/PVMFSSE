# Environment

```bash
sudo apt-get install -y build-essential autoconf libtool pkg-config
sudo apt-get install -y yasm openssl scons libssl-dev
sudo apt-get install -y libboost-dev
```

# get the code

get the main code

```bash
 git clone https://gitlab.com/sse/sophos.git
```

get the third-party code

```bash
git submodule update --init
```

# building

Building is done through SConstruct.
To build the submodules, you can either run

```bash
 $ scons deps
```

or do it by hand:

```bash
$ (cd third_party/crypto; scons lib); 
$ (cd third_party/ssdmap; scons lib); 
$ (cd third_party/db-parser; scons lib); 
```

Then, to build Sophos itself, just enter in your terminal
```bash
$ scons 
```

# issue 1

the version of libssl-dev too high： in bost, the version of libssl-dev is 1.0.0；is yours is 1.1.0，then there will have error `can not find the function AES_CTR`

the solution is that install libssl1.0-dev by aptitude

firstly add the follow line to `/etc/apt/sources.list`

```bash
deb http://security.debian.org/debian-security jessie/updates main 
```

then

```bash
aptitude update
aptitude install libssl1.0-dev
```

# issue 2

the version of rocksdb too high: in bost, the version of bost is too low, so he use some options which are no longer supported

we just need to comment the error line in his code