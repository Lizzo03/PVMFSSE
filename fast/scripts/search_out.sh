#!/bin/bash
cat benchmark_server.out | awk '{if($2=="10") {sum+=$5;count+=1}} END{print "10 matching documents, search time per matching entry(ms): ",sum/count}'
cat benchmark_server.out | awk '{if($2=="100") {sum+=$5;count+=1}} END{print "100 matching documents, search time per matching entry(ms): ",sum/count}'
cat benchmark_server.out | awk '{if($2=="1000") {sum+=$5;count+=1}} END{print "1000 matching documents, search time per matching entry(ms): ",sum/count}'
cat benchmark_server.out | awk '{if($2=="10000") {sum+=$5;count+=1}} END{print "10000 matching documents, search time per matching entry(ms): ",sum/count}'
cat benchmark_server.out | awk '{if($2=="100000") {sum+=$5;count+=1}} END{print "100000 matching documents, search time per matching entry(ms): ",sum/count}'