LDFLAGS = -L/usr/local/lib `pkg-config --libs protobuf grpc++`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl -lprotobuf -lrocksdb -lz -lcryptopp -lpthread -O3 -lpbc -lgmp

CXX = g++
CPPFLAGS += `pkg-config --cflags protobuf grpc` -I/usr/local/include -I/usr/local/include/cryptopp -I. -pthread
CXXFLAGS += -std=c++11 -O3

GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`

all: data_owner data_user private_server public_server

data_owner: DistSSE.pb.o DistSSE.grpc.pb.o data_owner.o DistSSE.Util.o
	$(CXX) $^ $(LDFLAGS) -o $@

data_user: DistSSE.pb.o DistSSE.grpc.pb.o data_user.o DistSSE.Util.o
	$(CXX) $^ $(LDFLAGS) -o $@

private_server: DistSSE.pb.o DistSSE.grpc.pb.o private_server.o DistSSE.Util.o
	$(CXX) $^ $(LDFLAGS) -o $@

public_server: DistSSE.pb.o DistSSE.grpc.pb.o public_server.o DistSSE.Util.o
	$(CXX) $^ $(LDFLAGS) -o $@

%.grpc.pb.cc: %.proto
	protoc --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

%.pb.cc: %.proto
	protoc --cpp_out=. $<

clean:
	rm -f *.o *.pb.cc *.pb.h data_owner data_user private_server public_server