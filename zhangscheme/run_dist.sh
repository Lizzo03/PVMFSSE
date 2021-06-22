#!/bin/bash
export CPLUS_INCLUDE_PATH=./include:$CPLUS_INCLUDE_PATH
g++ DistSSE.Util.h logger.h logger.cc DistSSE.Util.cc DistSSE.server.h DistSSE_server.cc DistSSE.pb.h DistSSE.pb.cc  DistSSE.grpc.pb.h DistSSE.grpc.pb.cc -L. -lrocksdb -lcryptopp -lgrpc++ -lgrpc -lprotobuf  -lpthread -o server -std=c++11 -O2
g++ DistSSE.Util.h logger.h logger.cc DistSSE.Util.cc DistSSE_client.cc DistSSE.pb.h DistSSE.pb.cc  DistSSE.grpc.pb.h DistSSE.grpc.pb.cc -L. -lrocksdb -lcryptopp -lgrpc++ -lgrpc -lprotobuf  -ldl -lpthread -o client -std=c++11 -O2
