#!/bin/bash
./rpc_client /tmp/fast.cdb 10 keyword_10e1 2 1 benchmark_client_10e1.update.out
./rpc_client /tmp/fast.cdb 100 keyword_10e2 2 1 benchmark_client_10e2.update.out
./rpc_client /tmp/fast.cdb 1000 keyword_10e3 2 1 benchmark_client_10e3.update.out
./rpc_client /tmp/fast.cdb 10000 keyword_10e4 2 1 benchmark_client_10e4.update.out
./rpc_client /tmp/fast.cdb 100000 keyword_10e5 2 1 benchmark_client_10e5.update.out

repeat_num=10 #在这里设置重复实验次数
for i in `seq 0 $repeat_num`;
do
    ./rpc_client /tmp/fast.cdb 10 keyword_10e1 3 1 benchmark_client_10e1.search.out
	./rpc_client /tmp/fast.cdb 100 keyword_10e2 3 1 benchmark_client_10e2.search.out
	./rpc_client /tmp/fast.cdb 1000 keyword_10e3 3 1 benchmark_client_10e3.search.out
	./rpc_client /tmp/fast.cdb 10000 keyword_10e4 3 1 benchmark_client_10e4.search.out
	./rpc_client /tmp/fast.cdb 100000 keyword_10e5 3 1 benchmark_client_10e5.search.out
done