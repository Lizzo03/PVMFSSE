#!/bin/bash
cat benchmark_client_10e1.verify.out | awk '{print "time of verify 10 entry (ms): " $4}'
cat benchmark_client_10e2.verify.out | awk '{print "time of verify 100 entry (ms): " $4}'
cat benchmark_client_10e3.verify.out | awk '{print "time of verify 1000 entry (ms): " $4}'
cat benchmark_client_10e4.verify.out | awk '{print "time of verify 10000 entry (ms): " $4}'
cat benchmark_client_10e5.verify.out | awk '{print "time of verify  100000 entry (ms): " $4}'