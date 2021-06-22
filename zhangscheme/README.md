# build

```bash
$ make clean
$ make
```

# functions test

this part is to prove the code is right and completely implement our scheme

## server side
 
```bash
# path of database, path of cache dadabase, number of threads, path of output log
$ ./rpc_server /tmp/my.sdb /tmp/my.scadb 1 benchmark_server.out
```

## client side
```bash
# insert one keyword-filename pair
./rpc_client /tmp/my.cdb 1

# insert three keyword-docuemnt pairs
./rpc_client /tmp/my.cdb 2

# search `keyword`
./rpc_client /tmp/my.cdb 3

# search and verify `keyword`
./rpc_client /tmp/my.cdb 4
```

# benchmark

## server

```bash
# path of database, path of cache dadabase, number of threads, path of output log
./rpc_server /tmp/my.sdb /tmp/my.scadb 1 benchmark_server.out
```
## Update
```bash
# path of database, number of entries, keyword, flag, number of threads, path of logfile
./rpc_client /tmp/my.cdb 10 keyword_10e1 2 1 benchmark_client_10e1.update.out
./rpc_client /tmp/my.cdb 100 keyword_10e2 2 1 benchmark_client_10e2.update.out
./rpc_client /tmp/my.cdb 1000 keyword_10e3 2 1 benchmark_client_10e3.update.out
./rpc_client /tmp/my.cdb 10000 keyword_10e4 2 1 benchmark_client_10e4.update.out
./rpc_client /tmp/my.cdb 100000 keyword_10e5 2 1 benchmark_client_10e5.update.out
```
## Search
```bash
# path of database, number of entries, keyword, flag, number of threads, path of logfile
./rpc_client /tmp/my.cdb 4 keyword_10e1 3 1 benchmark_client_10e1.search.out
./rpc_client /tmp/my.cdb 4 keyword_10e2 3 1 benchmark_client_10e2.search.out
./rpc_client /tmp/my.cdb 4 keyword_10e3 3 1 benchmark_client_10e3.search.out
./rpc_client /tmp/my.cdb 4 keyword_10e4 3 1 benchmark_client_10e4.search.out
./rpc_client /tmp/my.cdb 4 keyword_10e5 3 1 benchmark_client_10e5.search.out
```

## Verify
```bash
# path of database, number of entries, keyword, flag, number of threads, path of logfile
./rpc_client /tmp/my.cdb 10 keyword_10e1 4 1 benchmark_client_10e1.verify.out
./rpc_client /tmp/my.cdb 100 keyword_10e2 4 1 benchmark_client_10e2.verify.out
./rpc_client /tmp/my.cdb 1000 keyword_10e3 4 1 benchmark_client_10e3.verify.out
./rpc_client /tmp/my.cdb 10000 keyword_10e4 4 1 benchmark_client_10e4.verify.out
./rpc_client /tmp/my.cdb 100000 keyword_10e5 4 1 benchmark_client_10e5.verify.out
```

# core code

```cplusplus
gen_update_token(){
    sc = get_search_time(w);
    tw = gen_enc_token(w);
    uc = get_update_time(w);
    l = Util::H1(tw + std::to_string(uc + 1));
    e = Util::Xor(op + ind, Util::H2(tw + std::to_string(uc + 1)));
    set_update_time(w, uc + 1);
    // search_time is used to store the proof
    set_search_time(w, Xor(sc, ind));
}

gen_search_token(){
    tw = gen_enc_token(w);
    uc = get_update_time(w);
}

search() {
    for(i=uc to 1){
        u = H1(tw + uc);
        e = get(u);
        (op, ind) = Xor(e, u);
    }
}
```

# use scripts

## Update

```bash
sh ./scripts/clear.sh
sh ./scripts/runserver.sh
sh ./scripts/update_batch.sh
# see output
sh ./scripts/update_out.sh
```

## Search

```bash
sh ./scripts/clear.sh
sh ./scripts/runserver.sh
sh ./scripts/search_batch.sh
# see output
sh ./scripts/search_out.sh
```

## Verify

```bash
sh ./scripts/clear.sh
sh ./scripts/runserver.sh
sh ./scripts/verify_batch.sh
# see output
sh ./scripts/verify_out.sh
```