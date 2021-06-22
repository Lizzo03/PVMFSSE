#!/bin/bash
# 多次运行减少偏差
./client -b 14e5.csdb -u keyword_10e1 -c 10 -v benchmark_client_10e1.update.out
./client -b 14e5.csdb -u keyword_10e1 -c 10 -v benchmark_client_10e1.update.out
./client -b 14e5.csdb -u keyword_10e1 -c 10 -v benchmark_client_10e1.update.out
./client -b 14e5.csdb -u keyword_10e2 -c 100 -v benchmark_client_10e2.update.out
./client -b 14e5.csdb -u keyword_10e3 -c 1000 -v benchmark_client_10e3.update.out
./client -b 14e5.csdb -u keyword_10e4 -c 10000 -v benchmark_client_10e4.update.out
./client -b 14e5.csdb -u keyword_10e5 -c 100000 -v benchmark_client_10e5.update.out