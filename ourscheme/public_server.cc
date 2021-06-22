//
// data_owner.cc
// Created by leo on 2020/1/31.
//

#include <string>
#include <thread>
#include<cstdio>
#include <grpcpp/grpcpp.h>
#include "DistSSE.grpc.pb.h"
#include "DistSSE.Util.h"
#include "/usr/local/include/pbc/pbc.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::Status;

using DistSSE::MathTest;
using DistSSE::MathRequest;
using DistSSE::MathReply;

using DistSSE::RPC;
using DistSSE::Registration;
using DistSSE::Update;
using DistSSE::Search;
using DistSSE::Revocation;
using DistSSE::ExecuteStatus;

using DistSSE::Util;

using grpc::Channel;
using grpc::ClientContext;
using namespace CryptoPP;

byte k_s[17] = "0123456789abcdef";
byte k_r[17] = "0123456789abcdef";
byte k_1[17] = "0123456789abcdef";
byte k_2[17] = "0123456789abcdef";
byte k_3[17] = "0123456789abcdef";
byte kid_1[17] = "0123456789abcdef";
std::string g_setup = "0123456789abcdef";
pairing_t pairing;
element_t g;

rocksdb::DB *ss_db;

void abort(int signum) {
    delete ss_db;
    exit(signum);
}

void setup() {
//            int rbits = 160;
//            int qbits = 512;
//            pbc_param_ptr param;
//            pairing_t pairing;
    char param[1024];
    FILE *pFile;
    pFile = fopen("a.param", "r");
    size_t count = fread(param, 1, 1024, pFile); // 读大小为1的个数最大为1024到param，返回真实读入的个数
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
//            pbc_param_init_a_gen(param, rbits, qbits);
//            pairing_init_pbc_param(pairing, param);
//            element_t g;
    element_init_G1(g, pairing);
    element_from_hash(g, &g_setup, g_setup.length());
//            element_printf("%d\n", g);

    std::string db_path = "/tmp/pubS.sdb";
    remove("/tmp/pubS.sdb");
    signal(SIGINT, abort);
    rocksdb::Options options;
    options.create_if_missing = true;
    Util::set_db_common_options(options);
    rocksdb::Status s1 = rocksdb::DB::Open(options, db_path, &ss_db);
    if (!s1.ok()) {
        std::cerr << "open ssdb error:" << s1.ToString() << std::endl;
    }
}

int store(rocksdb::DB *&db, const std::string l, const std::string e) {
    rocksdb::Status s;
    rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
    s = db->Put(write_option, l, e);
    assert(s.ok());
    if (s.ok()) return 0;
    else {
        return -1;
    }
}

std::string get(rocksdb::DB *&db, const std::string l) {
    std::string tmp;
    rocksdb::Status s;
    db->Get(rocksdb::ReadOptions(), l, &tmp);
    return tmp;
}

void gen_search_token(std::string token, std::unordered_set<std::string> &result) {
    std::vector<std::string> elems3;
    Util::split(token, ',', elems3);
    std::string stc1 = Util::hex2str(elems3[1]);
    std::string tw = Util::hex2str(elems3[0]);
//    std::cout << "token: " << token << std::endl;

    while (stc1.compare("00000000") != 0) {
//        std::cout << "tw: " << Util::str2hex(tw) << std::endl;
//        std::cout << "stc1: " << stc1 << std::endl;
        std::string adr = Util::H1(tw + stc1);
        std::string e;
        e = get(ss_db, adr);
        std::vector<std::string> elems4;
        Util::split(Util::Xor(e, Util::H2(tw + stc1)), ',', elems4);
//        std::cout << "adr: " << Util::str2hex(adr) << std::endl;
//        std::cout << "e: " << Util::str2hex(e) << std::endl;
//        std::cout << "value: " << Util::Xor(e, Util::H2(tw + stc1)) << std::endl;
        stc1 = Util::hex2str(elems4[0]);
        std::string ind = Util::hex2str(elems4[2]);
        result.insert(ind);
//        std::cout << "stc2: " << stc1 << std::endl;
//        std::cout << "ind: " << ind << std::endl;
//        std::cout << "result size: " << result.size() << std::endl;
//        if (result.size() == 576)
//            break;
    }
}

class PubSClient {
public:
    PubSClient(std::shared_ptr<Channel> channel) : stub_(RPC::NewStub(channel)) {}

    bool search(std::unordered_set<std::string> result) {
        Search request;
        for (std::string ind : result) {
            request.add_sf(ind);
        }
        ExecuteStatus reply;
        ClientContext context;
        Status status = stub_->search(&context, request, &reply);
        if (status.ok()) {
            return reply.status();
        } else {
            std::cout << status.error_code() << ": " << status.error_message() << std::endl;
            return -1;
        }
    }

private:
    std::unique_ptr<RPC::Stub> stub_;
};

class PubSServiceImplementation final : public RPC::Service {
    Status update(ServerContext *context, const Update *request, ExecuteStatus *reply) override {
        std::string adrf = request->adrf();
        std::string e = request->e();
        store(ss_db, adrf, e);

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "             Update Received              " << std::endl;
//        std::cout << "------adrf: " << Util::str2hex(adrf) << std::endl;
//        std::cout << "------e: " << Util::str2hex(e) << std::endl;
        return Status::OK;
    }

    Status batch_update(ServerContext *context, ServerReader <Update> *reader, ExecuteStatus *response) {
        std::string adrf;
        std::string e;
        Update request;
        while (reader->Read(&request)) {
            adrf = request.adrf();
            e = request.e();
            store(ss_db, adrf, e);
        }
        response->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "             Update Received              " << std::endl;
        return Status::OK;
    }

    Status search(ServerContext *context, const Search *request, ExecuteStatus *reply) override {
        std::string token = request->token();
        std::unordered_set<std::string> result;
        gen_search_token(token, result);
//        std::cout << "result size: " << result.size() << std::endl;
        std::string address("0.0.0.0:5001");
        PubSClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        client.search(result);

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "             Search Received              " << std::endl;
//        std::cout << "------token: " << token << std::endl;
        return Status::OK;
    }
};

void server_job() {
    setup();
    std::string address("0.0.0.0:5003");
    PubSServiceImplementation service;
    ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "-----------------------------------------------" << std::endl;
    std::cout << "Public Server listening on port: " << address << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;
    server->Wait();
}

int main(int argc, char **argv) {
//    Run();
    server_job();
    return 0;
}