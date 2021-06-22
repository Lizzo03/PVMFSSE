#!/bin/bash
./rpc_client /tmp/my.cdb 10 keyword_10e1 2 1 benchmark_client_10e1.update.out
./rpc_client /tmp/my.cdb 100 keyword_10e2 2 1 benchmark_client_10e2.update.out
./rpc_client /tmp/my.cdb 1000 keyword_10e3 2 1 benchmark_client_10e3.update.out
./rpc_client /tmp/my.cdb 10000 keyword_10e4 2 1 benchmark_client_10e4.update.out
./rpc_client /tmp/my.cdb 100000 keyword_10e5 2 1 benchmark_client_10e5.update.out

repeat_num=10 #在这里设置重复实验次数
for i in `seq 0 $repeat_num`;
do
    ./rpc_client /tmp/my.cdb 10 keyword_10e1 4 1 benchmark_client_10e1.verify.out
	./rpc_client /tmp/my.cdb 100 keyword_10e2 4 1 benchmark_client_10e2.verify.out
	./rpc_client /tmp/my.cdb 1000 keyword_10e3 4 1 benchmark_client_10e3.verify.out
	./rpc_client /tmp/my.cdb 10000 keyword_10e4 4 1 benchmark_client_10e4.verify.out
	./rpc_client /tmp/my.cdb 100000 keyword_10e5 4 1 benchmark_client_10e5.verify.out
done