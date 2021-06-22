#!/bin/bash
export CPLUS_INCLUDE_PATH=./include:$CPLUS_INCLUDE_PATH
g++ DistSSE.Util.h DistSSE.Util.cc server.cc  -L. -lpthread -lrocksdb -lcryptopp  -o server -std=c++11 -O2

