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
using DistSSE::Update;
using DistSSE::Revocation;
using DistSSE::ExecuteStatus;

using DistSSE::Util;

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientWriterInterface;
using namespace CryptoPP;

std::mutex list_mtx;
std::mutex W_mtx;
std::map<std::string, std::string> W_mapper;
std::map<std::string, std::string> list_mapper;

byte k_s[17] = "0123456789abcdef";
byte k_r[17] = "0123456789abcdef";
byte k_1[17] = "0123456789abcdef";
byte k_2[17] = "0123456789abcdef";
byte k_3[17] = "0123456789abcdef";
byte kid_1[17] = "0123456789abcdef";
std::string g_setup = "0123456789abcdef";
std::string eid_local;
pairing_t pairing;
element_t g;
int k_s_length = 16;

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

int set_W_list(std::string w, std::string value) {
    //设置单词w更新次数为update_time
    {
        std::lock_guard<std::mutex> lock(W_mtx);
        W_mapper[w] = value;
    }
    // no need to store, because ti will be done in ~Client
    // store(w + "_search", std::to_string(search_time));
    return 0;
}

std::string get_W_list(std::string w) {
//    int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
//    std::stringstream ss;
//    ss << std::setw(ind_len) << std::setfill('0') << 0;
    std::string value = "00000000";
//    ss >> value;
    value = Util::str2hex("00000000") + ',' + Util::str2hex(value);
    std::map<std::string, std::string>::iterator it;
    it = W_mapper.find(w);
    if (it != W_mapper.end()) {
        value = it->second;
    } else {
        set_W_list(w, value);
    }
    return value;
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
}

void gen_register_token(std::string uid, std::string &eid, std::string &qkid, std::string &qkcid, std::string &kid) {
//    eid = "eid1";
//    qkid = "qkid1";
//    qkcid = "qkcid1";
//    kid = "kid1";
    element_t oid_e, ks_e, qkid_e, qkcid_e, ks_qk_e;
    //Only for simulating u2uid
    std::to_string(rand() % 10000);

    eid = gen_enc_token(uid, k_1);
    //Store eid for revocation
    eid_local = eid;
    element_init_Zr(oid_e, pairing);
    element_random(oid_e);
    element_init_Zr(ks_e, pairing);
    element_init_Zr(qkid_e, pairing);
    element_init_Zr(ks_qk_e, pairing);
    element_init_G1(qkcid_e, pairing);
    size_t n = element_length_in_bytes(oid_e);
    byte oid_c[n];
    element_to_bytes(oid_c, oid_e);
    std::string oid = Util::byte2str(oid_c, n);
    qkid = gen_enc_token(Util::str2hex(eid) + ',' + Util::str2hex(oid), k_2);
    std::string k_s_string = Util::byte2str(k_s, k_s_length);
    element_from_hash(ks_e, &k_s_string, k_s_string.length());
    element_from_hash(qkid_e, &qkid, qkid.length());
//    element_from_bytes(ks_e, k_s);
//    element_from_bytes(qkid_e, Util::str2byte(qkid));
    element_div(ks_qk_e, ks_e, qkid_e);
    element_pow_zn(qkcid_e, g, ks_qk_e);
    n = element_length_in_bytes(qkcid_e);
    byte qkcid_c[n];
    element_to_bytes(qkcid_c, qkcid_e);
    qkcid = Util::byte2str(qkcid_c, n);
    kid = std::to_string(rand() % 10000);
    set_user_list(eid, Util::str2hex(qkid) + ',' + Util::str2hex(kid));
}

void gen_update_token2(std::string w, std::string &tw, std::string &rw, std::string &adrw) {
    tw = gen_enc_token(w, k_s);
    rw = gen_enc_token(w + "0", k_r);
//    std::string adrf, e, wst;

    element_t h_w_e, hw_g_pair_e, hw_g_pair_ks_e, ks_e;
    element_init_Zr(ks_e, pairing);
    std::string k_s_string = Util::byte2str(k_s, k_s_length);
    element_from_hash(ks_e, &k_s_string, k_s_string.length());
//    element_from_bytes(ks_e, k_s);
    element_init_G2(h_w_e, pairing);
    element_init_GT(hw_g_pair_e, pairing);
    element_init_GT(hw_g_pair_ks_e, pairing);

    element_from_hash(h_w_e, &w, w.length());

    element_pairing(hw_g_pair_e, g, h_w_e);

    element_pow_zn(hw_g_pair_ks_e, hw_g_pair_e, ks_e);

    size_t n = element_length_in_bytes(hw_g_pair_ks_e);
    byte adrw_b[n];
    element_to_bytes(adrw_b, hw_g_pair_ks_e);
    adrw = Util::byte2str(adrw_b, n);

    //Only for simulation
    adrw = w;
}

void
gen_update_token(std::string tw, std::string rw, std::string adrw, std::string op, std::string w, std::string ind,
                 std::string &wst, std::string &adrf, std::string &e) {
    std::string stc, hash, stc1, hash_p;
    std::vector<std::string> elems;
    Util::split(get_W_list(w), ',', elems);
    stc = Util::hex2str(elems[0]);
    hash = Util::hex2str(elems[1]);
    //    srand(std::stoi(ind + w));
//    stc1 = std::to_string(rand() % 100000000);
    stc1 = ind;
//    std::cout << "stc: " << stc1 << std::endl;
    e = Util::Xor(Util::str2hex(stc) + ',' + Util::str2hex(op) + ',' + Util::str2hex(ind), Util::H2(tw + stc1));
    hash_p = Util::Xor(hash, Util::H1(rw + tw + ind));
    hash_p = Util::Xor(hash_p, Util::H1(rw + stc));
    hash_p = Util::Xor(hash_p, Util::H1(rw + stc1));
    //store hash_p
    set_W_list(w, Util::str2hex(stc1) + ',' + Util::str2hex(hash_p));
    adrf = Util::H1(tw + stc1);
    wst = gen_enc_token(Util::str2hex(adrw) + ',' + Util::str2hex(tw) + ',' + Util::str2hex(stc1) + ',' +
                        Util::str2hex(rw) + ',' + Util::str2hex(hash_p), k_3);
}

class DOClient {
public:
    DOClient(std::shared_ptr<Channel> channel) : stub_(RPC::NewStub(channel)) {}

    ~DOClient() {
//        std::cout << "DOClient has been deleted!" << std::endl;
    }

    bool registration(std::string eid, std::string qkid, std::string qkcid, std::string kid) {
        Registration request;
        request.set_eid(eid);
        request.set_qkid(qkid);
        request.set_qkcid(qkcid);
        request.set_kid(kid);
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

    bool update(std::string wst, std::string adrf, std::string e) {
        Update request;
        request.set_wst(wst);
        request.set_adrf(adrf);
        request.set_e(e);
        ExecuteStatus reply;
        ClientContext context;
        Status status = stub_->update(&context, request, &reply);
        if (status.ok()) {
            return reply.status();
        } else {
            std::cout << status.error_code() << ": " << status.error_message() << std::endl;
            return -1;
        }
    }

    bool batch_update(std::vector<std::string> wst_vector, std::vector<std::string> adrf_vector, std::vector<std::string> e_vector) {
        Update request;
        ClientContext context;
        ExecuteStatus exec_status;
        std::unique_ptr<ClientWriterInterface<Update>> writer(
                stub_->batch_update(&context, &exec_status));
        std::string wst, adrf, e;
        for (int i = 0; i < wst_vector.size(); ++i) {
            wst = wst_vector[i];
            adrf = adrf_vector[i];
            e = e_vector[i];
            request.set_wst(wst);
            request.set_adrf(adrf);
            request.set_e(e);
            writer->Write(request);
        }
        writer->WritesDone();
        Status status = writer->Finish();
        if (status.ok()) {
            return true;
        } else {
            std::cout << status.error_code() << ": " << status.error_message() << std::endl;
            return false;
        }
    }

    bool revocation(std::string eid) {
        std::vector<std::string> elems;
        Util::split(get_user_list(eid), ',', elems);
        std::string qkid = Util::hex2str(elems[0]);
        std::string value, uid;
        value = get_dec_token(qkid, k_2);
        std::vector<std::string> elems2;
        Util::split(value, ',', elems2);
        eid = DistSSE::Util::hex2str(elems2[0]);
        uid = get_dec_token(eid, k_1);
        std::cout << "Uid: " + uid + " has been deleted!" << std::endl;


        Revocation request;
        request.set_eid(eid);
        ExecuteStatus reply;
        ClientContext context;
        Status status = stub_->revocation(&context, request, &reply);
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

class DOServiceImplementation final : public RPC::Service {
    Status registration(ServerContext *context, const Registration *request, ExecuteStatus *reply) override {
        std::string uid = request->uid();
        std::string eid, qkid, qkcid, kid;
        gen_register_token(uid, eid, qkid, qkcid, kid);
        std::string address("0.0.0.0:5001");
        DOClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        bool response = client.registration(eid, qkid, qkcid, kid);

        std::string address2("0.0.0.0:5002");
        DOClient client2(grpc::CreateChannel(address2, grpc::InsecureChannelCredentials()));
        bool response2 = client2.registration(eid, qkid, qkcid, kid);

        reply->set_status(true);
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "         Registration Received            " << std::endl;
//        std::cout << "------uid: " << uid << std::endl;
        return Status::OK;
    }
};

void server_job() {
    std::string address("0.0.0.0:5000");
    DOServiceImplementation service;
    ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Data Owner listening on port: " << address << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    server->Wait();
}

void client_job() {
    setup();
    bool flag = true;
    sleep(1);
    while (flag) {
        int condition;
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "Please select an operation:" << std::endl;
        std::cout << "1. Update" << std::endl;
        std::cout << "2. Batch update" << std::endl;
        std::cout << "3. Revocation" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << "------------------------------------------" << std::endl;
        std::cin >> condition;
        switch (condition) {
            case 1: {
                std::string address("0.0.0.0:5002");
                DOClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
                std::string address2("0.0.0.0:5003");
                DOClient client2(grpc::CreateChannel(address2, grpc::InsecureChannelCredentials()));
                std::string op, w, ind, wst, adrf, e, tw, rw, adrw;
                op = "1";
                w = "keyword111";
                ind = "ind1";
                struct timeval t1, t2;
                gettimeofday(&t1, NULL);
                gen_update_token2(w, tw, rw, adrw);
                gen_update_token(tw, rw, adrw, op, w, ind, wst, adrf, e);
                client.update(wst, adrf, e);
                client2.update(wst, adrf, e);
                gettimeofday(&t2, NULL);
                double update_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;
                std::cout << "------update time: " << update_time << " ms" << std::endl;
                break;
            }
            case 2: {
                std::string address("0.0.0.0:5002");
                DOClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
                std::string address2("0.0.0.0:5003");
                DOClient client2(grpc::CreateChannel(address2, grpc::InsecureChannelCredentials()));
                size_t N_entries;
                std::cout << "------------------------------------------" << std::endl;
                std::cout << "Please input batch update num:" << std::endl;
                std::cin >> N_entries;
                std::string w = "keyword111";
//                std::string tw = gen_enc_token(w, k_s);
                std::string tw, rw, adrw, ind, wst, adrf, e;
                std::string op = "1";
                struct timeval t1, t2;
                gettimeofday(&t1, NULL);
                gen_update_token2(w, tw, rw, adrw);
                std::vector<std::string> wst_vector;
                std::vector<std::string> adrf_vector;
                std::vector<std::string> e_vector;
                for (size_t i = 0; i < N_entries; i++) {
                    ind = std::to_string(i);
                    gen_update_token(tw, rw, adrw, op, w, ind, wst, adrf, e);
                    wst_vector.push_back(wst);
                    adrf_vector.push_back(adrf);
                    e_vector.push_back(e);
//                    std::cout <<  "adrf: " << Util::str2hex(adrf) << std::endl;
                }
                std::thread batch_update1(&DOClient::batch_update, &client, wst_vector, adrf_vector, e_vector);
                std::thread batch_update2(&DOClient::batch_update, &client2, wst_vector, adrf_vector, e_vector);
                batch_update1.join();
                batch_update2.join();
                gettimeofday(&t2, NULL);
                double update_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;
                std::cout << "------update time: " << update_time << " ms" << std::endl;
                break;
            }
            case 3: {
                std::string address("0.0.0.0:5002");
                DOClient client(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
                int response;
                std::string eid;
                eid = eid_local;
                response = client.revocation(eid);
//                std::cout << "Revocation Status: " << response << std::endl;
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
    std::thread server(server_job);
    std::thread client(client_job);
    server.join();
    client.join();
    return 0;
}