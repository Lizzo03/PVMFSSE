#include "DistSSE.client.h"
#include "DistSSE.Util.h"
#include <cmath>
#include <chrono>

namespace DistSSE {

    static std::mutex print_mtx;

    static bool sample(double value, double rate) {
        return (value - rate) < 0.0000000000000001 ? true : false;
    }

    static double rand_0_to_1() { //
        return ((double) rand() / (RAND_MAX));
    }

    static double rand_0_to_1(unsigned int seed) {
        srand(seed);
        return ((double) rand() / (RAND_MAX));
    }


    static void search_log(std::string word, int counter) {
        std::cout << word + "\t" + std::to_string(counter) << std::endl;
    }

    static void generation_job(Client *client, unsigned int thread_id, size_t N_entries, unsigned int step,
                               std::atomic_size_t *entries_counter) {
        const std::string kKeyword01PercentBase = "0.1";
        const std::string kKeyword1PercentBase = "1";
        const std::string kKeyword10PercentBase = "10";

        const std::string kKeywordGroupBase = "Group-";
        const std::string kKeyword10GroupBase = kKeywordGroupBase + "10^";

        constexpr uint32_t max_10_counter = ~0;
        size_t counter = thread_id;
        std::string id_string = std::to_string(thread_id);

        uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0;

        std::string keyword_01, keyword_1, keyword_10;
        std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_20, kw_30, kw_60;

        AutoSeededRandomPool prng;
        int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
        byte tmp[ind_len];


        // some data for trace
        double search_rate[3] = {0.0001, 0.001, 0.01};
        const std::string TraceKeywordGroupBase = "Trace";
        size_t counter_t = 1;
        std::string trace_2 = TraceKeywordGroupBase + "_" + id_string + "_2_5";
        std::string trace_1 = TraceKeywordGroupBase + "_" + id_string + "_1_5";
        std::string trace_0 = TraceKeywordGroupBase + "_" + id_string + "_0_5";
        std::string trace_2_st, trace_1_st, trace_0_st;
        //std::string l, e;
        // for gRPC
        UpdateRequestMessage request;
        ClientContext context;
        ExecuteStatus exec_status;
        std::unique_ptr <RPC::Stub> stub_(
                RPC::NewStub(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials())));
        std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(
                stub_->batch_update(&context, &exec_status));
        for (size_t i = 0; counter < N_entries; counter += step, i++) {
            prng.GenerateBlock(tmp, sizeof(tmp));
            std::string ind = (std::string((const char *) tmp, ind_len));
            std::string ind_01 = std::string((const char *) tmp, 3);
            std::string ind_1 = std::string((const char *) tmp + 3, 1);
            std::string ind_10 = std::string((const char *) tmp + 4, 1);
            keyword_01 = kKeyword01PercentBase + "_" + ind_01 + "_1"; //  randomly generated
            keyword_1 = kKeyword1PercentBase + "_" + ind_1 + "_1";
            keyword_10 = kKeyword10PercentBase + "_" + ind_10 + "_1";

            // logger::log(logger::INFO) << "k_01: " << keyword_01 << std::endl;

            writer->Write(client->gen_update_request("1", keyword_01, ind, 0));
            writer->Write(client->gen_update_request("1", keyword_1, ind, 0));
            writer->Write(client->gen_update_request("1", keyword_10, ind, 0));


            ind_01 = std::string((const char *) tmp + 5, 3);
            ind_1 = std::string((const char *) tmp + 8, 1);
            ind_10 = std::string((const char *) tmp + 9, 1);

            keyword_01 = kKeyword01PercentBase + "_" + ind_01 + "_2";
            keyword_1 = kKeyword1PercentBase + "_" + ind_1 + "_2";
            keyword_10 = kKeyword10PercentBase + "_" + ind_10 + "_2";

            writer->Write(client->gen_update_request("1", keyword_01, ind, 0));
            writer->Write(client->gen_update_request("1", keyword_1, ind, 0));
            writer->Write(client->gen_update_request("1", keyword_10, ind, 0));


            if (counter_10_1 < max_10_counter) {
                kw_10_1 = kKeyword10GroupBase + "1_" + id_string + "_" + std::to_string(counter_10_1);

                if ((i + 1) % 10 == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_1 << std::endl;
                    }
                    counter_10_1++;
                }
            }
            if (counter_20 < max_10_counter) {
                kw_20 = kKeywordGroupBase + "20_" + id_string + "_" + std::to_string(counter_20);

                if ((i + 1) % 20 == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_20 << std::endl;
                    }
                    counter_20++;
                }
            }
            if (counter_30 < max_10_counter) {
                kw_30 = kKeywordGroupBase + "30_" + id_string + "_" + std::to_string(counter_30);

                if ((i + 1) % 30 == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_30 << std::endl;
                    }
                    counter_30++;
                }
            }
            if (counter_60 < max_10_counter) {
                kw_60 = kKeywordGroupBase + "60_" + id_string + "_" + std::to_string(counter_60);

                if ((i + 1) % 60 == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_60 << std::endl;
                    }
                    counter_60++;
                }
            }
            if (counter_10_2 < max_10_counter) {
                kw_10_2 = kKeyword10GroupBase + "2_" + id_string + "_" + std::to_string(counter_10_2);

                if ((i + 1) % 100 == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_2 << std::endl;
                    }
                    counter_10_2++;
                }
            }
            if (counter_10_3 < max_10_counter) {
                kw_10_3 = kKeyword10GroupBase + "3_" + id_string + "_" + std::to_string(counter_10_3);

                if ((i + 1) % ((size_t)(1e3)) == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_3 << std::endl;
                    }
                    counter_10_3++;
                }
            }
            if (counter_10_4 < max_10_counter) {
                kw_10_4 = kKeyword10GroupBase + "4_" + id_string + "_" + std::to_string(counter_10_4);

                if ((i + 1) % ((size_t)(1e4)) == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_4 << std::endl;
                    }
                    counter_10_4++;
                }
            }
            if (counter_10_5 < max_10_counter) {
                kw_10_5 = kKeyword10GroupBase + "5_" + id_string + "_" + std::to_string(counter_10_5);

                if ((i + 1) % ((size_t)(1e5)) == 0) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_5 << std::endl;
                    }
                    counter_10_5++;
                }
            }


            (*entries_counter)++;
            if (((*entries_counter) % 10000) == 0) {
                {
                    std::lock_guard <std::mutex> lock(print_mtx);
                    logger::log(logger::INFO) << "Random DB generation: " << (*entries_counter)
                                              << " entries generated\r" << std::flush;
                }
            }


            writer->Write(client->gen_update_request("1", kw_10_1, ind, 0));
            writer->Write(client->gen_update_request("1", kw_10_2, ind, 0));
            writer->Write(client->gen_update_request("1", kw_10_3, ind, 0));
            writer->Write(client->gen_update_request("1", kw_10_4, ind, 0));
            writer->Write(client->gen_update_request("1", kw_10_5, ind, 0));
            //writer->Write( client->gen_update_request("1", kw_20, ind, 0));
            //writer->Write( client->gen_update_request("1", kw_30, ind, 0));
            //writer->Write( client->gen_update_request("1", kw_60, ind, 0));

            // perpare for trace simulation later
            if (counter_t <= 1e5) {
                // srand(N_entries + counter_t);

                writer->Write(client->gen_update_request("1", trace_2, ind, counter_t));
                writer->Write(client->gen_update_request("1", trace_1, ind, counter_t));
                writer->Write(client->gen_update_request("1", trace_0, ind, counter_t));

                counter_t++;
            }

        }

        // now tell server we have finished
        writer->WritesDone();
        Status status = writer->Finish();

        std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: (" +
                          std::to_string(counter_10_1) + ", "
                          + std::to_string(counter_10_2) + ", " + std::to_string(counter_10_3) + ", " +
                          std::to_string(counter_10_4) + ", "
                          + std::to_string(counter_10_5) + ")";
        logger::log(logger::INFO) << log << std::endl;
    }


    void gen_db(Client &client, size_t N_entries, unsigned int n_threads) {
        std::atomic_size_t entries_counter(0);
        // client->start_update_session();
        // unsigned int n_threads = std::thread::hardware_concurrency();
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;
        struct timeval t1, t2;
        gettimeofday(&t1, NULL);
        for (unsigned int i = 0; i < n_threads; i++) {
            threads.push_back(std::thread(generation_job, &client, i, N_entries, n_threads, &entries_counter));
        }
        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }
        gettimeofday(&t2, NULL);
        logger::log(logger::INFO) << "total update time: "
                                  << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                  << std::endl;

        // client->end_update_session();
    }

    /**
    *
    * @param client
    * @param thread_id 所在线程的id
    * @param N_entries 所在线程应该生成多少个entries
    */
    static void generation_job_2(Client *client, std::string keyword, unsigned int thread_id, size_t N_entries) {
        //std::string id_string = std::to_string(thread_id);
        CryptoPP::AutoSeededRandomPool prng;
        int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
        byte tmp[ind_len];
        // for gRPC
        UpdateRequestMessage request;
        ClientContext context;
        ExecuteStatus exec_status;
        std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
        std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
        for (size_t i = 0; i < N_entries; i++) {
            prng.GenerateBlock(tmp, sizeof(tmp));
            std::string ind = /*Util.str2hex*/(std::string((const char *) tmp, ind_len));
            writer->Write(client->gen_update_request("1", keyword, ind));
        }
        // now tell server we have finished
        writer->WritesDone();
        Status status = writer->Finish();

        std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: " +
                          std::to_string(N_entries) + " keyword-filename";
        logger::log(logger::INFO) << log << std::endl;
    }

    /**
    *
    * @param client
    * @param thread_id 所在线程的id
    * @param N_entries 所在线程应该生成多少个entries
    */
    static void generation_job_4(Client *client, unsigned int thread_id, size_t N_entries) {
        //std::string id_string = std::to_string(thread_id);
        CryptoPP::AutoSeededRandomPool prng;
        int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
        byte tmp[ind_len];
        byte tmp2[ind_len];
        // for gRPC
        UpdateRequestMessage request;
        ClientContext context;
        ExecuteStatus exec_status;
        std::unique_ptr <RPC::Stub> stub_(RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
        std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
        for (size_t i = 0; i < N_entries; i++) {
            prng.GenerateBlock(tmp, sizeof(tmp));
            std::string ind = /*Util.str2hex*/(std::string((const char *) tmp, ind_len));

            prng.GenerateBlock(tmp2, sizeof(tmp2));
            std::string keyword = /*Util.str2hex*/(std::string((const char *) tmp2, ind_len));

            writer->Write(client->gen_update_request("1", keyword, ind));
        }
        // now tell server we have finished
        writer->WritesDone();
        Status status = writer->Finish();

        std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: " +
                          std::to_string(N_entries) + " keyword-filename";
        logger::log(logger::INFO) << log << std::endl;
    }

  /**
  * 获得数据库
  * @param client 客户端对象
  * @param N_entries 全部的entries数目
  * @param keyword 关键词
  * @param n_threads 线程数
  */
    void gen_db_2(Client &client, size_t N_entries,std::string keyword, unsigned int n_threads) {
        logger::log(logger::INFO) << "in gen_db_2" << std::endl;
        // std::atomic_size_t entries_counter(0);
        // client->start_update_session();
        // unsigned int n_threads = std::thread::hardware_concurrency();
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;
        struct timeval t1, t2;
        gettimeofday(&t1, NULL);
        int numOfEntries1 = N_entries / n_threads;
        int numOfEntries2 = N_entries / n_threads + N_entries % n_threads;
        //std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: " + std::to_string(N_entries) + " keyword-filename";
        //logger::log(logger::INFO) << log << std::endl;
        //logger::log(logger::INFO) << std::to_string(numOfEntries1)+" "+std::to_string(numOfEntries2) << std::endl;
        for (unsigned int i = 0; i < n_threads - 1; i++) {
            threads.push_back(std::thread(generation_job_2, &client, keyword, i, numOfEntries1));
        }
        threads.push_back(std::thread(generation_job_2, &client,keyword, n_threads - 1, numOfEntries2));
        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }
        gettimeofday(&t2, NULL);
        logger::log_benchmark()<< "keyword: "+keyword+" "+std::to_string(N_entries)+" entries "+"update time: "
                               << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                               << std::endl;
        logger::log(logger::INFO)<< "keyword: "+keyword+" "+std::to_string(N_entries)+" entries "+"update time: "
                                 << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                 << std::endl;
        // client->end_update_session();
    }


    /**
  * 获得数据库
  * @param client 客户端对象
  * @param N_entries 全部的entries数目
  * @param n_threads 线程数
  */
    void gen_db_4(Client &client, size_t N_entries, unsigned int n_threads) {
        logger::log(logger::INFO) << "in gen_db_4" << std::endl;
        // std::atomic_size_t entries_counter(0);
        // client->start_update_session();
        // unsigned int n_threads = std::thread::hardware_concurrency();
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;
        struct timeval t1, t2;
        gettimeofday(&t1, NULL);
        int numOfEntries1 = N_entries / n_threads;
        int numOfEntries2 = N_entries / n_threads + N_entries % n_threads;
        //std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: " + std::to_string(N_entries) + " keyword-filename";
        //logger::log(logger::INFO) << log << std::endl;
        //logger::log(logger::INFO) << std::to_string(numOfEntries1)+" "+std::to_string(numOfEntries2) << std::endl;
        for (unsigned int i = 0; i < n_threads - 1; i++) {
            threads.push_back(std::thread(generation_job_4, &client, i, numOfEntries1));
        }
        threads.push_back(std::thread(generation_job_4, &client, n_threads - 1, numOfEntries2));
        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }
        gettimeofday(&t2, NULL);
        logger::log_benchmark()<< "keyword: " + std::to_string(N_entries)+" entries "+"update time: "
                               << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                               << std::endl;
        logger::log(logger::INFO)<< "keyword: "+ std::to_string(N_entries)+" entries "+"update time: "
                                 << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                 << std::endl;
        // client->end_update_session();
    }


    static void generation_job_3(Client *client, std::string keyword, unsigned int thread_id, size_t N_entries) {
        for (size_t i = 0; i < N_entries; i++) {
            int uc = client->get_update_time(keyword);
            client->set_update_time(keyword, uc + 1); // TODO
        }
        int uc = client->get_update_time(keyword);
        std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: " +
                          std::to_string(N_entries) + " keyword-filename " + std::to_string(uc)+" uc";
        logger::log(logger::INFO) << log << std::endl;
    }

  /**
  *
  * @param client 客户端对象
  * @param N_entries 全部的entries数目
  * @param keyword 关键词
  * @param n_threads 线程数
  */
    void gen_db_3(Client &client) {
        logger::log(logger::INFO) << "in gen_db_3" << std::endl;
        int N_entries = 100;
        int n_threads = 4;
        std::string keyword = "hello";
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;
        struct timeval t1, t2;
        gettimeofday(&t1, NULL);
        int numOfEntries1 = N_entries / n_threads;
        int numOfEntries2 = N_entries / n_threads + N_entries % n_threads;
        for (unsigned int i = 0; i < n_threads - 1; i++) {
            threads.push_back(std::thread(generation_job_3, &client, keyword, i, numOfEntries1));
        }
        threads.push_back(std::thread(generation_job_3, &client,keyword, n_threads - 1, numOfEntries2));
        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }
        gettimeofday(&t2, NULL);
        logger::log_benchmark()<< "keyword: "+keyword+" "+std::to_string(N_entries)+" entries "+"update time: "
                               << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                               << std::endl;
        logger::log(logger::INFO)<< "keyword: "+keyword+" "+std::to_string(N_entries)+" entries "+"update time: "
                                 << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                 << std::endl;
        int uc = client.get_update_time(keyword);
        std::string log = "now the number is " + std::to_string(uc);
        logger::log(logger::INFO) << log << std::endl;
        // client->end_update_session();
    }

//    static void generate_trace(Client *client, size_t N_entries) {
//        // randomly generate a large db
//        // gen_db(*client, N_entries, 4);
//        logger::log(logger::DBG) << "DB generation finished." << std::endl;
//
//        // then perform trace generation
//        const std::string TraceKeywordGroupBase = "Trace-";
//
//        AutoSeededRandomPool prng;
//        int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
//        byte tmp[ind_len];
//
//        UpdateRequestMessage request;
//        ClientContext context;
//        ExecuteStatus exec_status;
//        // std::unique_ptr<RPC::Stub> stub_(RPC::NewStub( grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials()) ) );
//        // std::unique_ptr<ClientWriterInterface<UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
//
//        // generate some trash data to certain large...
//        double search_rate[4] = {0.0001, 0.001, 0.01};
//        int delay_time[4] = {0, 0, 0};
//        std::string l, e;
//
//        bool not_repeat_search = true;
//        int search_time = 0, entries_counter = 0, update_time = 0;
//
//        srand(123);
//
//        Status s;
//        for (int i = 2; i >= 0; --i) {
//
//            // double search_rate = search_rate[i];
//            for (int j = 5; j <= 5; j++) {
//                std::string keyword = TraceKeywordGroupBase + "_" + std::to_string(i) + "_" + std::to_string(j);
//
//                for (int k = 0; k < pow(10, j); k++) {
//
//                    prng.GenerateBlock(tmp, sizeof(tmp));
//                    std::string ind = /*Util.str2hex*/(std::string((const char *) tmp, ind_len));
//
//                    entries_counter++;
//
//                    // bool success = writer->Write( client->gen_update_request("1", keyword, ind, k) );
//                    s = client->update(client->gen_update_request("1", keyword, ind, k));
//                    assert(s.ok());
//
//                    //if (k % 10 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay_time[i]));
//
//
//                    // search or not ??
//                    double r = rand_0_to_1();
//                    bool is_search = sample(r, search_rate[i]);
//
//                    if (is_search) {
//                        // 执行搜索
//                        //std::this_thread::sleep_for(std::chrono::milliseconds(delay_time[i]));
//                        client->search(keyword);
//                        search_time++;
//                        search_log(keyword, k);
//                    }
//
//                }// for k
//            }//for j
//        }//for i
//
//        logger::log(logger::INFO) << "Trace DB generation: " << ": " << (entries_counter) << " entries generated"
//                                  << std::endl;
//
//
//        logger::log(logger::INFO) << "search time: " << search_time << std::endl;
//
//        // now tell server we have finished
//        //writer->WritesDone();
//        //s = writer->Finish();
//        assert(s.ok());
//    }// generate_trace


    static void gen_rdb(std::string db_path, size_t N_entries) {

        rocksdb::DB *ss_db;

        rocksdb::Options options;
        options.create_if_missing = true;
        Util::set_db_common_options(options);

        rocksdb::Status s = rocksdb::DB::Open(options, db_path, &ss_db);

        if (!s.ok()) {
            std::cerr << "In gen_rdb_nrpc(), open db error: " << s.ToString() << std::endl;
        }

        int c = 0;

        AutoSeededRandomPool prng;
        int ind_len = AES::BLOCKSIZE; // AES::BLOCKSIZE = 16
        byte tmp[ind_len];


        for (int i = 0; i < N_entries; i++) {
            prng.GenerateBlock(tmp, sizeof(tmp));
            std::string key = (std::string((const char *) tmp, ind_len));
            prng.GenerateBlock(tmp, sizeof(tmp));
            std::string value = (std::string((const char *) tmp, ind_len / 2));
            s = ss_db->Put(rocksdb::WriteOptions(), key, value);
            c++;
            if (c % 100000 == 0)
                logger::log(logger::INFO) << "RDB generation: " << ": " << c << " entries generated\r" << std::flush;
        }

    }// gen_rdb

//    void eval_trace(Client &client, int thread_num) {
//        // for trace
//        double search_rate[3] = {0.0001, 0.001, 0.01};
//        const std::string TraceKeywordGroupBase = "Trace";
//        int last_uc;
//
//        for (int i = 0; i < thread_num; i++)
//            for (int j = 0; j < 3; j++) {
//                std::string w = TraceKeywordGroupBase + "_" + std::to_string(i) + "_" + std::to_string(j) + "_5";
//                last_uc = 0;
//                for (int c = 1; c <= 1e5; c++) {
//                    double r = rand_0_to_1(c);
//                    bool is_search = sample(r, search_rate[j]);
//                    if (is_search) {
//                        // last_uc = c;
//                        client.search_for_trace(w, c - last_uc);
//                        last_uc = c;
//                        search_log(w, c);
//                    }
//                }
//            }
//    }

} //namespace DistSSE
