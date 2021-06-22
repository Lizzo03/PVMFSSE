#!/bin/bash
rm -rf /tmp/*.db
./rpc_client /tmp/cdb.db 10 keyword_10e1 2 1 benchmark_client_10e1.setup.out
./rpc_client /tmp/cdb.db 100 keyword_10e2 2 1 benchmark_client_10e2.setup.out
./rpc_client /tmp/cdb.db 1000 keyword_10e3 2 1 benchmark_client_10e3.setup.out
./rpc_client /tmp/cdb.db 10000 keyword_10e4 2 1 benchmark_client_10e4.setup.out
./rpc_client /tmp/cdb.db 100000 keyword_10e5 2 1 benchmark_client_10e5.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other1 2 1 benchmark_client_other1.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other2 2 1 benchmark_client_other2.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other3 2 1 benchmark_client_other3.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other4 2 1 benchmark_client_other4.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other5 2 1 benchmark_client_other5.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other6 2 1 benchmark_client_other6.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other7 2 1 benchmark_client_other7.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other8 2 1 benchmark_client_other8.setup.out
# ./rpc_client /tmp/cdb.db 100000 keyword_other9 2 1 benchmark_client_other9.setup.out