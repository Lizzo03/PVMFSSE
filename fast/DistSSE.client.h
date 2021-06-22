/* 
 * Created by Xiangfu Song on 10/21/2016.
 * Email: bintasong@gmail.com
 * 
 */
#ifndef DISTSSE_CLIENT_H
#define DISTSSE_CLIENT_H

#include <grpc++/grpc++.h>

#include "DistSSE.grpc.pb.h"

#include "DistSSE.Util.h"

#include "logger.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReaderInterface;
using grpc::ClientWriterInterface;
using grpc::ClientAsyncResponseReaderInterface;

using grpc::Status;

using namespace CryptoPP;

// 用来生成 kw
byte k_s[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";

extern int max_keyword_length;
extern int max_nodes_number;

namespace DistSSE {

    class Client {
    private:
        std::unique_ptr <RPC::Stub> stub_;
        rocksdb::DB *cs_db;
        std::mutex sc_mtx;
        std::mutex uc_mtx;
        std::map <std::string, size_t> sc_mapper;
        std::map <std::string, size_t> uc_mapper;
    public:
        Client(std::shared_ptr <Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)) {
            rocksdb::Options options;
            // Util::set_db_common_options(options);
            // set options for merge operation
            rocksdb::Options simple_options;
            simple_options.create_if_missing = true;
            simple_options.merge_operator.reset(new rocksdb::StringAppendOperator());
            simple_options.use_fsync = true;
            rocksdb::Status status = rocksdb::DB::Open(simple_options, db_path, &cs_db);
            // load all sc, uc to memory
            rocksdb::Iterator *it = cs_db->NewIterator(rocksdb::ReadOptions());
            std::string key;
            std::string value;
            size_t counter = 0;
            for (it->SeekToFirst(); it->Valid(); it->Next()) {
                key = it->key().ToString();
                value = it->value().ToString();
                std::cout << key +" "+ value << std::endl;
                if (key[0] == 's') {
                    sc_mapper[key.substr(1, key.length() - 1)] = std::stoi(value);
                } else {
                    uc_mapper[key.substr(1, key.length() - 1)] = std::stoi(value);
                }
                counter++;
            }

            // assert( it->status().ok() ); // Check for any errors found during the scan
            /*if(it->status().ok() == 0 ) */{
                std::cout << "client db status: " << it->status().ToString() << std::endl;
            }
            delete it;
            std::cout << "Just remind, previous keyword counter: " << counter / 2 << std::endl;
        }

        ~Client() {

            // must store 'sc' and 'uc' to disk

            size_t keyword_counter = 0;
            std::map<std::string, size_t>::iterator it;
            for (it = sc_mapper.begin(); it != sc_mapper.end(); ++it) {
                store("s" + it->first, std::to_string(it->second));
                keyword_counter++;
            }

            for (it = uc_mapper.begin(); it != uc_mapper.end(); ++it) {
                store("u" + it->first, std::to_string(it->second));
            }
            std::cout << "Total keyword: " << keyword_counter << std::endl;

            delete cs_db;

            std::cout << "Bye~ " << std::endl;
        }
        int store(const std::string k, const std::string v) {
            rocksdb::Status s = cs_db->Delete(rocksdb::WriteOptions(), k);
            s = cs_db->Put(rocksdb::WriteOptions(), k, v);
            if (s.ok()) return 0;
            else return -1;
        }

        std::string get(const std::string k) {
            std::string tmp;
            rocksdb::Status s = cs_db->Get(rocksdb::ReadOptions(), k, &tmp);
            if (s.ok()) return tmp;
            else return "";
        }

        int get_search_time(std::string w) {

            int search_time = 0;

            std::map<std::string, size_t>::iterator it;

            it = sc_mapper.find(w);

            if (it != sc_mapper.end()) {
                search_time = it->second;
            } else {
                // std::string value = get("s" + w );

                // search_time = value == "" ? 0 : std::stoi(value);

                set_search_time(w, search_time); // cache search_time into sc_mapper
            }
            return search_time;
        }

        int set_search_time(std::string w, int search_time) {
            //设置单词w更新次数为update_time
            {
                std::lock_guard <std::mutex> lock(sc_mtx);
                sc_mapper[w] = search_time;
            }
            // no need to store, because ti will be done in ~Client
            // store(w + "_search", std::to_string(search_time));
            return 0;
        }

        void increase_search_time(std::string w) {
            {
                // std::lock_guard<std::mutex> lock(sc_mtx);
                set_search_time(w, get_search_time(w) + 1);
            }
        }

        size_t get_update_time(std::string w) {
            size_t update_time = 0;
            std::map<std::string, size_t>::iterator it;
            it = uc_mapper.find(w);
            if (it != uc_mapper.end()) {
                update_time = it->second; // TODO need to lock when read, but for our scheme, no need
            } else {
                // std::string value = get("u" + w );
                // update_time = value == "" ? 0 : std::stoi(value);
                set_update_time(w, update_time);
            }
            return update_time;
        }

        int set_update_time(std::string w, int update_time) {
            {
                //std::lock_guard <std::mutex> lock(uc_mtx);
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                uc_mapper[w] = update_time;
            }
            return 0;
        }

        void increase_update_time(std::string w) {
            {
                //std::lock_guard<std::mutex> lock(uc_mtx);
                set_update_time(w, get_update_time(w) + 1);
            }
        }

        std::string gen_enc_token(const std::string token) {
            // 使用padding方式将所有字符串补齐到16的整数倍长度
            std::string token_padding;
            std::string enc_token;
            try {
                CFB_Mode<AES>::Encryption e;
                e.SetKeyWithIV(k_s, AES128_KEY_LEN, iv_s, (size_t) AES::BLOCKSIZE);
                token_padding = Util::padding(token);
                byte cipher_text[token_padding.length()];
                e.ProcessData(cipher_text, (byte *) token_padding.c_str(), token_padding.length());
                enc_token = std::string((const char *) cipher_text, token_padding.length());
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_enc_token() " << e.what() << std::endl;
                exit(1);
            }
            return enc_token;
        }

        void gen_update_token(std::string op, std::string w, std::string ind, std::string &l, std::string &e) {
            try {
                std::string enc_token;
                std::string kw, tw;
                // get update time of `w` for `node`
                size_t sc, uc;

                uc = get_update_time(w);
                sc = get_search_time(w);
                // tw = gen_enc_token(k_s, AES128_KEY_LEN, iv_s, w + "|" + std::to_string(-1) );
                // 模拟F
                tw = gen_enc_token(w);
                // 模拟P
                gen_enc_token(w);

                // generating update pair, which is (l, e)
                l = Util::H1(tw + std::to_string(uc + 1));
                e = Util::Xor(op + ind, Util::H2(tw + std::to_string(uc + 1)));
                increase_update_time(w);
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_update_token() " << e.what() << std::endl;
                exit(1);
            }
        }

        UpdateRequestMessage gen_update_request(std::string op, std::string w, std::string ind, int counter) {
            try {
                std::string enc_token;
                UpdateRequestMessage msg;

                std::string kw, tw, l, e;
                // get update time of `w` for `node`
                size_t sc, uc;
                uc = get_update_time(w);
                sc = get_search_time(w);
                tw = gen_enc_token(w);
                //For simulating P and k
                gen_enc_token(w);
                std::to_string(rand() % 100000000);
                l = Util::H1(tw + std::to_string(uc + 1));
                e = Util::Xor(op + ind, Util::H2(tw + std::to_string(uc + 1)));
                msg.set_l(l);
                msg.set_e(e);
                msg.set_counter(counter);
                set_update_time(w, uc + 1); // TODO
                return msg;
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_update_request() " << e.what() << std::endl;
                exit(1);
            }
        }

        UpdateRequestMessage gen_update_request(std::string op, std::string w, std::string ind) {
            try {
                std::string enc_token;
                UpdateRequestMessage msg;

                std::string kw, tw, l, e;
                // get update time of `w` for `node`
                size_t sc, uc;
                uc = get_update_time(w);
                sc = get_search_time(w);
                tw = gen_enc_token(w);
                //For simulating P and k
                gen_enc_token(w);
                std::to_string(rand() % 100000000);
                l = Util::H1(tw + std::to_string(uc + 1));
                e = Util::Xor(op + ind, Util::H2(tw + std::to_string(uc + 1)));
                msg.set_l(l);
                msg.set_e(e);
                msg.set_counter(0);
                set_update_time(w, uc + 1); // TODO
                return msg;
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_update_request() " << e.what() << std::endl;
                exit(1);
            }
        }

//        // only used for simulation ...
//        CacheRequestMessage gen_cache_request(std::string keyword, std::string inds) {
//            try {
//                CacheRequestMessage msg;
//                std::string tw = gen_enc_token(keyword + "|" + std::to_string(-1));
//                msg.set_tw(tw);
//                msg.set_inds(inds);
//                return msg;
//            }
//            catch (const CryptoPP::Exception &e) {
//                std::cerr << "in gen_cache_request() " << e.what() << std::endl;
//                exit(1);
//            }
//        }

        void gen_search_token(std::string w, std::string &kw, std::string &tw, size_t &uc) {
            try {
                // get update time of
                int sc;
                uc = get_update_time(w);
                sc = get_search_time(w);
                tw = gen_enc_token(w);
                if (uc != 0) kw = gen_enc_token(tw + std::to_string(uc));
                else kw = gen_enc_token(tw + "cache");
                //else kw = "";
            } catch (const CryptoPP::Exception &e) {
                std::cerr << "in gen_search_token() " << e.what() << std::endl;
                exit(1);
            }
        }


//
//        std::string search_for_trace(const std::string w, int uc) { // only used for trace simulation
//            std::string kw, tw;
//            int sc = get_search_time(w);
//            tw = gen_enc_token(w);
//            if (uc != 0) kw = gen_enc_token(tw + "|" + std::to_string(uc));
//            else kw = gen_enc_token(tw + "|" + "cache");
//            search(kw, tw, uc);
//            // don't need to update sc and uc for trace simulation
//            // increase_search_time(w);
//            // set_update_time(w, 0);
//            return "OK";
//        }
        // 客户端RPC通信部分
        std::string search(const std::string w) {
            logger::log(logger::INFO) << "client search(const std::string w):  " << std::endl;
            struct timeval t1, t2;
            gettimeofday(&t1, NULL);
            std::string kw, tw;
            size_t uc;
            gen_search_token(w, kw, tw, uc);
            search(kw, tw, uc);
            // update `sc` and `uc`
            increase_search_time(w);
            //set_update_time(w, 0);
            gettimeofday(&t2, NULL);
            double search_time = ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0;
            logger::log(logger::INFO) << "search time (ms): "<< search_time << std::endl;
            return "OK";
        }

        std::string search(const std::string kw, const std::string tw, int uc) {
            // request包含 enc_token 和 st
            SearchRequestMessage request;
            request.set_kw(kw);
            request.set_tw(tw);
            request.set_uc(uc);
            // Context for the client. It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
            ClientContext context;
            // 执行RPC操作，返回类型为 std::unique_ptr<ClientReaderInterface<SearchReply>>
            std::unique_ptr <ClientReaderInterface<SearchReply>> reader = stub_->search(&context, request);
            // 读取返回列表
            int counter = 0;
            SearchReply reply;
            while (reader->Read(&reply)) {
//                logger::log(logger::INFO) << reply.ind()<<std::endl;
                counter++;
            }
            logger::log(logger::INFO) << "search result: "<< counter << std::endl;
            return "OK";
        }

//        Status update(UpdateRequestMessage update) {
//            ClientContext context;
//            ExecuteStatus exec_status;
//            // 执行RPC
//            Status status = stub_->update(&context, update, &exec_status);
//            // if(status.ok()) increase_update_time(w);
//            return status;
//        }

        Status update(std::string op, std::string w, std::string ind) {
            logger::log(logger::INFO) << "client update(op, w, ind):  " << std::endl;
            ClientContext context;
            ExecuteStatus exec_status;
            // 执行RPC
            std::string l, e;
            gen_update_token(op, w, ind, l, e); // update(op, w, ind, _l, _e);
            UpdateRequestMessage update_request;
            update_request.set_l(l);
            update_request.set_e(e);
            Status status = stub_->update(&context, update_request, &exec_status);
            //if(status.ok()) increase_update_time(w);
            return status;
        }

        Status batch_update(std::string keyword, size_t N_entries) {
            logger::log(logger::INFO) << "client batch_update(std::string keyword, size_t N_entries)" << std::endl;
            //std::string id_string = std::to_string(thread_id);
            CryptoPP::AutoSeededRandomPool prng;
            int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
            byte tmp[ind_len];
            // for gRPC
            UpdateRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
            for (size_t i = 0; i < N_entries; i++) {
                prng.GenerateBlock(tmp, sizeof(tmp));
                std::string ind = /*Util.str2hex*/(std::string((const char *) tmp, ind_len));
                writer->Write(gen_update_request("1", keyword, ind));
            }
            // now tell server we have finished
            writer->WritesDone();
            Status status = writer->Finish();
            if(status.ok()) {
                //set_update_time(keyword, get_update_time(keyword) + N_entries);
                std::string log = "Random DB generation: completed: " + std::to_string(N_entries) + " keyword-filename";
                logger::log(logger::INFO) << log << std::endl;
            }
            return status;
        }
//
//        Status batch_update(std::vector <UpdateRequestMessage> update_list) {
//            UpdateRequestMessage request;
//            ClientContext context;
//            ExecuteStatus exec_status;
//            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(
//                    stub_->batch_update(&context, &exec_status));
//            int i = 0;
//            while (i < update_list.size()) {
//                writer->Write(update_list[i]);
//            }
//            writer->WritesDone();
//            Status status = writer->Finish();
//            return status;
//        }


//        void test_upload(int wsize, int dsize) {
//            std::string l, e;
//            for (int i = 0; i < wsize; i++)
//                for (int j = 0; j < dsize; j++) {
//                    gen_update_token("1", std::to_string(i), std::to_string(j), l, e); // update(op, w, ind, _l, _e);
//                    UpdateRequestMessage update_request;
//                    update_request.set_l(l);
//                    update_request.set_e(e);
//                    // logger::log(logger::INFO) << "client.test_upload(), l:" << l <<std::endl;
//                    Status s = update(update_request); // TODO
//                    // if (s.ok()) increase_update_time( std::to_string(i) );
//
//                    if ((i * dsize + j) % 1000 == 0)
//                        logger::log(logger::INFO) << " updating :  " << i * dsize + j << "\r" << std::flush;
//                }
//        }
    };

} // namespace DistSSE

#endif // DISTSSE_CLIENT_H
