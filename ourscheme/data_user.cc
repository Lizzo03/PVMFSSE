//
// data_owner.cc
// Created by leo on 2020/1/31.
//

#include <string>
#include <thread>
#include <grpcpp/grpcpp.h>
#include "DistSSE.grpc.pb.h"
#include "unistd.h"
#include "DistSSE.Util.h"
#include "/usr/local/include/pbc/pbc.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using DistSSE::MathTest;
using DistSSE::MathRequest;
using DistSSE::MathReply;

using DistSSE::RPC;
using DistSSE::Registration;
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

std::string eid;
std::string qkid;
std::string kid;
std::string rst;
std::unordered_set<std::string> sfResult;

bool rstFlag = false;
bool sfFlag = false;

struct timeval t1, t2;
//gettimeofday(&t1, NULL);
//gettimeofday(&t2, NULL);
//double search_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;

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

void gen_search_token(std::string w, std::string qkid, std::string &trid) {
//    trid = "trid1";
    element_t Trid_e, qkid_e, h_w_e;
    element_init_G1(Trid_e, pairing);
    element_init_Zr(qkid_e, pairing);
    element_init_G2(h_w_e, pairing);
    element_from_hash(h_w_e, &w, w.length());
    element_from_hash(qkid_e, &qkid, qkid.length());
//    element_from_bytes(qkid_e, Util::str2byte(qkid));
    element_pow_zn(Trid_e, h_w_e, qkid_e);
    size_t n = element_length_in_bytes(Trid_e);
    byte Trid_b[n];
    element_to_bytes(Trid_b, Trid_e);
    trid = Util::byte2str(Trid_b, n);
    //Only for simulation
    trid = w;
//    std::cout << "n: " << n << std::endl;
//    std::cout << "gen_search_token_trid1: " << Util::byte2str(Trid_b, n) << std::endl;
//    std::cout << "gen_search_token_trid2: " << Trid_b[0] << std::endl;
//    std::cout << "gen_search_token_trid: " << trid << std::endl;
}

void verification(std::string rst, std::unordered_set<std::string> result) {
    std::string tw, rw, stc, hash;
    byte *kid_b = Util::str2byte(kid);
    std::string value = get_dec_token(rst, kid_1);
    std::vector<std::string> elems;
    Util::split(value, ',', elems);
    tw = Util::hex2str(elems[0]);
    stc = Util::hex2str(elems[1]);
    rw = Util::hex2str(elems[2]);
    hash = Util::hex2str(elems[3]);
//    int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
//    std::stringstream ss;
//    ss << std::setw(ind_len) << std::setfill('0') << 0;
    std::string hash_p = "00000000";
//    ss >> hash_p;
    hash_p = Util::Xor(hash_p, Util::H1(rw + stc));
    hash_p = Util::Xor(hash_p, Util::H1(rw + "00000000"));
    for (std::unordered_set<std::string>::iterator i = result.begin(); i != result.end(); i++) {
        hash_p = Util::Xor(hash_p, Util::H1(rw + tw + *i));
    }
//    std::cout << "------hash_p: " << Util::str2hex(hash_p) << std::endl;
//    std::cout << "------hash  : " << Util::str2hex(hash) << std::endl;
//    if (!hash_p.compare(hash))
//        std::cout << "             Verify Accept!               " << std::endl;
//    else
//        std::cout << "             Verify Reject!               " << std::endl;
}

class DUServiceImplementation final : public RPC::Service {
    Status registration(ServerContext *context, const Registration *request, ExecuteStatus *reply) override {
        eid = request->eid();
        qkid = request->qkid();
        kid = request->kid();

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "         Registration Received            " << std::endl;
//        std::cout << "------eid: " << Util::str2hex(eid) << std::endl;
//        std::cout << "------qkid: " << Util::str2hex(qkid) << std::endl;
//        std::cout << "------kid: " << Util::str2hex(kid) << std::endl;
        return Status::OK;
    }

    Status search(ServerContext *context, const Search *request, ExecuteStatus *reply) override {
        std::string rst_tmp = request->rst();
        if (!rst_tmp.empty()) {
//            std::cout << "------rst: " << Util::str2hex(rst_tmp) << std::endl;
            rst = rst_tmp;
            rstFlag = true;
        } else {
            std::cout << "------------------------------------------" << std::endl;
            std::cout << "            Search Received               " << std::endl;
            std::unordered_set<std::string> result;
            for (int i = 0; i < request->sf_size(); ++i) {
//                std::cout << "------sf(" + std::to_string(i + 1) + "): " << request->sf(i) << std::endl;
                result.insert(request->sf(i));
            }
            std::cout << "------search result: " << result.size() << std::endl;
            sfResult = result;
            sfFlag = true;
        }
        if (rstFlag && sfFlag) {
            gettimeofday(&t2, NULL);
            double search_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;
            std::cout << "------search time: "<< search_time << " ms" << std::endl;
            rstFlag = false;
            sfFlag = false;
            gettimeofday(&t1, NULL);
            verification(rst, sfResult);
            gettimeofday(&t2, NULL);
            double verify_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;
            std::cout << "------verify time: "<< verify_time << " ms" << std::endl;
        }

        reply->set_status(true);
        return Status::OK;
    }
};

class DUClient {
public:
    DUClient(std::shared_ptr<Channel> channel) : stub_(RPC::NewStub(channel)) {}

    ~DUClient() {
//        std::cout << "DUClient has been deleted!" << std::endl;
    }

    bool registration(std::string uid) {
        Registration request;
        uid = "user1";
        request.set_uid(uid);
        ExecuteStatus reply;
        ClientContext context;
        Status status = stub_->registration(&context, request, &reply);
        if (status.ok()) {
            return reply.status();
        } else {
            std::cout << status.error_code() << ": " << status.error_message() << std::endl;
            return -1;
        }
    }

    bool search(std::string trid, std::string eid) {
        Search request;
        request.set_trid(trid);
        request.set_eid(eid);
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

void server_job() {
    std::string address("0.0.0.0:5001");
    DUServiceImplementation service;
    ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Data User listening on port: " << address << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    server->Wait();
}

void client_job() {
    setup();
    sleep(1);
    bool flag = true;
    while (flag) {
        int condition;
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "Please select an operation:" << std::endl;
        std::cout << "1. Registration" << std::endl;
        std::cout << "2. Search" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << "------------------------------------------" << std::endl;
        std::cin >> condition;
        switch (condition) {
            case 1: {
                std::string address("0.0.0.0:5000");
                DUClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
                int response;
                std::string uid;
                uid = "user1";
                response = client.registration(uid);
//                std::cout << "Registration Status: " << response << std::endl;
                break;
            }
            case 2: {
                gettimeofday(&t1, NULL);
                std::string address("0.0.0.0:5002");
                DUClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
                int response;
                std::string w, qkid, trid;
                w = "keyword111";
                gen_search_token(w, qkid, trid);
//                std::cout << "trid: " << Util::str2hex(trid) << std::endl;
                response = client.search(trid, eid);
//                std::cout << "Search Status: " << response << std::endl;
                break;
            }
            case 0: {
                flag = false;
                break;
            }
            default:
                std::cout << "Default Option!" << std::endl;
        }
    }
}

void run_parallel() {
    std::thread server(server_job);
    std::thread client(client_job);
    server.join();
    client.join();
}

int main(int argc, char **argv) {
//    Run();
    std::thread server(server_job);
    std::thread client(client_job);
    server.join();
    client.join();
    return 0;
}