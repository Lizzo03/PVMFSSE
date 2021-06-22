#!/bin/bash
cat benchmark_client_10e1.update.out | awk '{print "time of update 10 entry (ms): " $7}'
cat benchmark_client_10e2.update.out | awk '{print "time of update 100 entry (ms): " $7}'
cat benchmark_client_10e3.update.out | awk '{print "time of update 1000 entry (ms): " $7}'
cat benchmark_client_10e4.update.out | awk '{print "time of update 10000 entry (ms): " $7}'
cat benchmark_client_10e5.update.out | awk '{print "time of update 100000 entry (ms): " $7}'