#!/bin/bash
cat benchmark_client_10e1.setup.out | awk '{print "time of update 10 entry (ms): " $7}'
cat benchmark_client_10e2.setup.out | awk '{print "time of update 100 entry (ms): " $7}'
cat benchmark_client_10e3.setup.out | awk '{print "time of update 1000 entry (ms): " $7}'
cat benchmark_client_10e4.setup.out | awk '{print "time of update 10000 entry (ms): " $7}'
cat benchmark_client_10e5.setup.out | awk '{print "time of update 100000 entry (ms): " $7}'