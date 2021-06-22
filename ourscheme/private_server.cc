//
// data_owner.cc
// Created by leo on 2020/1/31.
//

#include <string>
#include <thread>
#include<stdio.h>
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

std::mutex list_mtx;
std::map<std::string, std::string> list_mapper;
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
//    element_random(g);
//    element_from_bytes(g, g_b);
    element_from_hash(g, &g_setup, g_setup.length());
//            element_printf("%d\n", g);

    std::string db_path = "/tmp/priS.sdb";
    remove("/tmp/priS.sdb");
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

std::string gen_enc_token(const std::string token, const byte *key) {
    // 使用padding方式将所有字符串补齐到16的整数倍长度
    std::string enc_token, token_padding;
    try {
//                token_padding = Util::padding(token);
        enc_token = DistSSE::Util::Enc(key, AES128_KEY_LEN, token);
    }
    catch (const CryptoPP::Exception &e) {
        std::cerr << "in gen_enc_token() " << e.what() << std::endl;
        exit(1);
    }
    return enc_token;
}

std::string get_dec_token(const std::string enc_token, const byte *key) {
    // 使用padding方式将所有字符串补齐到16的整数倍长度
    std::string dec_token;
    try {
        dec_token = DistSSE::Util::Dec(key, AES128_KEY_LEN, enc_token);
//                dec_token = Util::remove_padding(dec_token);
    }
    catch (const CryptoPP::Exception &e) {
        std::cerr << "in get_dec_token() " << e.what() << std::endl;
        exit(1);
    }
    return dec_token;
}

int set_user_list(std::string eid, std::string value) {
    {
        std::lock_guard<std::mutex> lock(list_mtx);
        list_mapper[eid] = value;
    }
    return 0;
}

std::string get_user_list(std::string eid) {
    std::string value;
    std::map<std::string, std::string>::iterator it;
    it = list_mapper.find(eid);
    if (it != list_mapper.end()) {
        value = it->second;
    } else {
        return "NULL";
    }
    return value;
}

void gen_search_token(std::string trid, std::string eid, std::string &token, std::string &rst) {
    std::string qkcid, kid, ind;
    std::vector<std::string> elems;
    Util::split(get_user_list(eid), ',', elems);
    qkcid = Util::hex2str(elems[0]);
    kid = Util::hex2str(elems[1]);

    element_t Tru, Tru_qk_pair, qkcid_e;
    element_init_GT(Tru_qk_pair, pairing);
    element_init_G1(qkcid_e, pairing);
    element_init_G1(Tru, pairing);
    element_from_bytes(Tru, Util::str2byte(trid));
    element_from_bytes(qkcid_e, Util::str2byte(qkcid));
    element_pairing(Tru_qk_pair, Tru, qkcid_e);

    size_t n1 = element_length_in_bytes(Tru_qk_pair);
    byte Tr_b[n1];
    element_to_bytes(Tr_b, Tru_qk_pair);
    std::string Tr = Util::byte2str(Tr_b, n1);
    //Only for simulation
    Tr = trid;

    std::vector<std::string> elems2;
    Util::split(get(ss_db, Tr), ',', elems2);
    std::string tw = elems2[0];
    std::string stc = elems2[1];
    std::string rw = elems2[2];
    std::string hash_p = elems2[3];
    byte *kid_b = Util::str2byte(kid);
    rst = gen_enc_token(tw + ',' + stc + ',' + rw + ',' + hash_p, kid_1);
    token = tw + ',' + stc;
}

class PriSClient {
public:
    PriSClient(std::shared_ptr<Channel> channel) : stub_(RPC::NewStub(channel)) {}

    bool search(std::string token, std::string rst) {
        Search request;
        request.set_token(token);
        request.set_rst(rst);
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

class PriSServiceImplementation final : public RPC::Service {
    Status registration(ServerContext *context, const Registration *request, ExecuteStatus *reply) override {
        std::string eid = request->eid();
        std::string qkcid = request->qkcid();
        std::string kid = request->kid();
        set_user_list(eid, Util::str2hex(qkcid) + ',' + Util::str2hex(kid));

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "          Registration Received           " << std::endl;
//        std::cout << "------eid: " << Util::str2hex(eid) << std::endl;
//        std::cout << "------qkcid: " << Util::str2hex(qkcid) << std::endl;
//        std::cout << "------kid: " << Util::str2hex(kid) << std::endl;
        return Status::OK;
    }

    Status update(ServerContext *context, const Update *request, ExecuteStatus *reply) override {
        std::string wst = request->wst();
        std::vector<std::string> elems2;
        Util::split(get_dec_token(wst, k_3), ',', elems2);
        std::string adrw = Util::hex2str(elems2[0]);
        store(ss_db, adrw, elems2[1] + ',' + elems2[2] + ',' + elems2[3] + ',' + elems2[4]);

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "              Update Received             " << std::endl;
//        std::cout << "------wst: " << Util::str2hex(wst) << std::endl;
        return Status::OK;
    }

    Status batch_update(ServerContext *context, ServerReader <Update> *reader, ExecuteStatus *response) {
        std::string wst;
        Update request;
        while (reader->Read(&request)) {
            wst = request.wst();
            std::vector<std::string> elems2;
            Util::split(get_dec_token(wst, k_3), ',', elems2);
            std::string adrw = Util::hex2str(elems2[0]);
            store(ss_db, adrw, elems2[1] + ',' + elems2[2] + ',' + elems2[3] + ',' + elems2[4]);
        }
        response->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "              Update Received             " << std::endl;
        return Status::OK;
    }

    Status search(ServerContext *context, const Search *request, ExecuteStatus *reply) override {
        std::string trid = request->trid();
        std::string eid = request->eid();

        std::string token, rst;
        gen_search_token(trid, eid, token, rst);

        std::string address("0.0.0.0:5003");
        PriSClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        bool response = client.search(token, rst);

        std::string address2("0.0.0.0:5001");
        PriSClient client2(grpc::CreateChannel(address2, grpc::InsecureChannelCredentials()));
        bool response2 = client2.search(token, rst);

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "             Search Received              " << std::endl;
//        std::cout << "------trid: " << Util::str2hex(trid) << std::endl;
//        std::cout << "------eid: " << Util::str2hex(eid) << std::endl;
        return Status::OK;
    }

    Status revocation(ServerContext *context, const Revocation *request, ExecuteStatus *reply) override {
        std::string eid = request->eid();
        set_user_list(eid, "NULL");

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "           Revocation Received            " << std::endl;
//        std::cout << "------eid: " << Util::str2hex(eid) << std::endl;
        return Status::OK;
    }
};

void server_job() {
    setup();
    std::string address("0.0.0.0:5002");
    PriSServiceImplementation service;
    ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout << "-----------------------------------------------" << std::endl;
    std::cout << "Private Server listening on port: " << address << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;
    server->Wait();
}

//void client_job() {
//    while (true) {
//
//    }
//}

//void run_parallel() {
//    std::thread server(server_job);
//    std::thread client(client_job);
//    server.join();
//    client.join();
//}

int main(int argc, char **argv) {
    server_job();
    return 0;
}