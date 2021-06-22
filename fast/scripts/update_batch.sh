#!/bin/bash
rm -rf /tmp/*.db
./rpc_client /tmp/fast.cdb 10 keyword_10e1 2 1 benchmark_client_10e1.update.out
./rpc_client /tmp/fast.cdb 100 keyword_10e2 2 1 benchmark_client_10e2.update.out
./rpc_client /tmp/fast.cdb 1000 keyword_10e3 2 1 benchmark_client_10e3.update.out
./rpc_client /tmp/fast.cdb 10000 keyword_10e4 2 1 benchmark_client_10e4.update.out
./rpc_client /tmp/fast.cdb 100000 keyword_10e5 2 1 benchmark_client_10e5.update.out
./rpc_client /tmp/cdb.db 100000 keyword_other1 2 1 benchmark_client_other1.out
./rpc_client /tmp/cdb.db 100000 keyword_other2 2 1 benchmark_client_other2.out
./rpc_client /tmp/cdb.db 100000 keyword_other3 2 1 benchmark_client_other3.out
./rpc_client /tmp/cdb.db 100000 keyword_other4 2 1 benchmark_client_other4.out
./rpc_client /tmp/cdb.db 100000 keyword_other5 2 1 benchmark_client_other5.out
./rpc_client /tmp/cdb.db 100000 keyword_other6 2 1 benchmark_client_other6.out
./rpc_client /tmp/cdb.db 100000 keyword_other7 2 1 benchmark_client_other7.out
./rpc_client /tmp/cdb.db 100000 keyword_other8 2 1 benchmark_client_other8.out
./rpc_client /tmp/cdb.db 100000 keyword_other9 2 1 benchmark_client_other9.out