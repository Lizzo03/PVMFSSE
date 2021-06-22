# functions test

## server
```bash
# path of database, path of cache dadabase, number of threads, path of output log
./rpc_server /tmp/fast.sdb /tmp/fast.scadb 1 benchmark_server.out
```
## client
```bash
# insert one keyword-filename pair
./rpc_client /tmp/fast.cdb 1

# insert three keyword-docuemnt pairs
./rpc_client /tmp/fast.cdb 2

# search `keyword`
./rpc_client /tmp/fast.cdb 3
```

# generate random database

insert directly to database, no RPC latency included

```bash
# path of database, number of keyword-filename pairs
./random_db /tmp/random.sdb 100
```

# benchmark
## Update
```bash
# path of database, number of entries, keyword, flag, number of threads, path of logfile
./rpc_client /tmp/fast.cdb 100 keyword_10e2 2 1 benchmark_client_10e2.update.out
./rpc_client /tmp/fast.cdb 1000 keyword_10e3 2 1 benchmark_client_10e3.update.out
./rpc_client /tmp/fast.cdb 10000 keyword_10e4 2 1 benchmark_client_10e4.update.out
./rpc_client /tmp/fast.cdb 100000 keyword_10e5 2 1 benchmark_client_10e5.update.out
```
## Search
```bash
# path of database, number of entries, keyword, flag, number of threads, path of logfile
./rpc_client /tmp/fast.cdb 4 keyword_10e2 3 1 benchmark_client_10e2.search.out
./rpc_client /tmp/fast.cdb 4 keyword_10e3 3 1 benchmark_client_10e3.search.out
./rpc_client /tmp/fast.cdb 4 keyword_10e4 3 1 benchmark_client_10e4.search.out
./rpc_client /tmp/fast.cdb 4 keyword_10e5 3 1 benchmark_client_10e5.search.out
```

# core code
```cplusplus
gen_update_token(){
    uc = get_update_time(w);
    tw = gen_enc_token(w);
    l = H1(tw+(uc+1));
    e = XOR((op+ind),H2(tw+(uc+1)))
}
gen_search_token(){
    uc = get_update_time(w);
    tw = gen_enc_token(w);
    kw = gen_enc_token(tw+uc);
}
```

# use scripts
## Update
```bash
sh ./scripts/clear.sh
sh ./scripts/runserver.sh
sh ./scripts/update_batch.sh
sh ./scripts/update_out.sh
```

## Search
```bash
sh ./scripts/clear.sh
sh ./scripts/runserver.sh
sh ./scripts/search_batch.sh
sh ./scripts/search_out.sh
```