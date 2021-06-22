#ifndef DISTSSE_TRACE_H
#define DISTSSE_TRACE_H

#include "DistSSE.client.h"
#include "DistSSE.Util.h"


namespace DistSSE {

    static bool sample(double value, double rate) {
        double _value = value;
        _value -= rate;
        return _value < 0.000000001 ? true : false;
    }

    static double rand_0_to_1() { //
        return ((double) rand() / (RAND_MAX));
    }

    void log_trace(int thread_id, int index, int type, std::string record) {
        //
        /*
        std::ofstream out("thread_" + std::to_string(thread_id) + "_.trace", std::ios::out|std::ios::app);
        if (out.is_open()) {
            out << std::to_string(index) + "\t" + std::to_string(type)+ "\t" + record +"\n";
            out.close();
        }*/
        std::cout << std::to_string(index) + "\t" + std::to_string(type) + "\t" + record + "\n" << std::endl;
    }

    static void generate_job_from_trace(Client *client, unsigned int thread_id, unsigned int step,
                                        std::atomic_size_t *entries_counter) {
        // unimplemented, generate db from existing trace

        return;
    }

    static void generate_job_from_trace(Client *client, unsigned int thread_id, size_t N_entries, unsigned int step,
                                        std::atomic_size_t *entries_counter) {
        // unimplemented, generate db from existing search trace, since update is determanistic

        return;
    }

    static void
    generation_trace(Client *client, unsigned int thread_id, size_t N_entries, unsigned int step, double search_rate,
                     std::atomic_size_t *entries_counter) {

        const std::string kKeywordGroupBase = "Group-";
        const std::string kKeyword10GroupBase = kKeywordGroupBase + "10^";

        constexpr uint32_t max_10_counter = ~0;
        size_t counter = thread_id;
        std::string id_string = std::to_string(thread_id);

        uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0;

        // the longer the list is, the more frequent it's updated
        std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_20, kw_30, kw_60;

        AutoSeededRandomPool prng;
        int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
        byte tmp[ind_len];

        double search_or_update[2] = {search_rate, 1.0 - search_rate};
        double search_level[4] = {1.00, 0.75, 0.5, 0.25};

        // for gRPC
        UpdateRequestMessage request;

        ClientContext context;

        ExecuteStatus exec_status;

        std::unique_ptr <RPC::Stub> stub_(
                RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));

        std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> writer(
                stub_->batch_update(&context, &exec_status));

        bool not_repeat_search = true;
        srand(thread_id);
        int search_time = 0;
        for (size_t i = 0; counter < N_entries;) {

            double r = rand_0_to_1();
            bool is_search = sample(r, search_rate);


            if (!is_search) {// if not a search query

                prng.GenerateBlock(tmp, sizeof(tmp));
                std::string ind = /*Util.str2hex*/(std::string((const char *) tmp, ind_len));


                if (counter_10_1 < max_10_counter) {
                    kw_10_1 = kKeyword10GroupBase + "1_" + id_string + "_" + std::to_string(counter_10_1);

                    if ((i + 1) % 10 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_1 << std::endl;
                        }*/
                        counter_10_1++;
                    }
                }
                if (counter_20 < max_10_counter) {
                    kw_20 = kKeywordGroupBase + "20_" + id_string + "_" + std::to_string(counter_20);

                    if ((i + 1) % 20 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_20 << std::endl;
                        }*/
                        counter_20++;
                    }
                }
                if (counter_30 < max_10_counter) {
                    kw_30 = kKeywordGroupBase + "30_" + id_string + "_" + std::to_string(counter_30);

                    if ((i + 1) % 30 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_30 << std::endl;
                        }*/
                        counter_30++;
                    }
                }
                if (counter_60 < max_10_counter) {
                    kw_60 = kKeywordGroupBase + "60_" + id_string + "_" + std::to_string(counter_60);

                    if ((i + 1) % 60 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_60 << std::endl;
                        }*/
                        counter_60++;
                    }
                }
                if (counter_10_2 < max_10_counter) {
                    kw_10_2 = kKeyword10GroupBase + "2_" + id_string + "_" + std::to_string(counter_10_2);

                    if ((i + 1) % 100 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_2 << std::endl;
                        }*/
                        counter_10_2++;
                    }
                }
                if (counter_10_3 < max_10_counter) {
                    kw_10_3 = kKeyword10GroupBase + "3_" + id_string + "_" + std::to_string(counter_10_3);

                    if ((i + 1) % ((size_t)(1e3)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_3 << std::endl;
                        }*/
                        counter_10_3++;
                    }
                }
                if (counter_10_4 < max_10_counter) {
                    kw_10_4 = kKeyword10GroupBase + "4_" + id_string + "_" + std::to_string(counter_10_4);

                    if ((i + 1) % ((size_t)(1e4)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_4 << std::endl;
                        }*/
                        counter_10_4++;
                    }
                }
                if (counter_10_5 < max_10_counter) {
                    kw_10_5 = kKeyword10GroupBase + "5_" + id_string + "_" + std::to_string(counter_10_5);

                    if ((i + 1) % ((size_t)(1e5)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_5 << std::endl;
                        }*/
                        counter_10_5++;
                    }
                }


                (*entries_counter)++;
                if (((*entries_counter) % 100) == 0) {
                    logger::log(logger::INFO) << "Random DB generation: " << ": " << (*entries_counter)
                                              << " entries generated\r" << std::flush;
                }

                writer->Write(client->gen_update_request("1", kw_10_1, ind));
                writer->Write(client->gen_update_request("1", kw_10_2, ind));
                writer->Write(client->gen_update_request("1", kw_10_3, ind));
                writer->Write(client->gen_update_request("1", kw_10_4, ind));
                writer->Write(client->gen_update_request("1", kw_10_5, ind));
                writer->Write(client->gen_update_request("1", kw_20, ind));
                writer->Write(client->gen_update_request("1", kw_30, ind));
                writer->Write(client->gen_update_request("1", kw_60, ind));



                // only update counts
                counter += step;
                i++;
                not_repeat_search = true;
            } else if (not_repeat_search) {
                // perform search query
                double u = rand_0_to_1();
                bool sure_to_search = sample(u, search_level[thread_id % 4]);
                if (sure_to_search) {

                    client->search(kw_10_1);
                    client->search(kw_10_2);
                    client->search(kw_10_3);
                    client->search(kw_10_4);
                    client->search(kw_10_5);
                    client->search(kw_20);
                    client->search(kw_30);
                    client->search(kw_60);

                    // std::string record = kw_10_1+","+kw_10_2+","+kw_10_3+","+kw_10_4+","+kw_10_5+","+kw_20+","+kw_30+","+kw_60;
                    // log_trace(thread_id, i, 1, record); // log for search query
                    search_time++;
                    not_repeat_search = false;
                    logger::log(logger::INFO) << search_time << std::endl;

                }// end	else
            }// end if
        } // end for

        // now tell server we have finished
        writer->WritesDone();
        Status status = writer->Finish();

        // std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: (" + std::to_string(counter_10_1) + ", "+ std::to_string(counter_10_2) + ", "+ std::to_string(counter_10_3) + ", "+ std::to_string(counter_10_4) + ", "+ std::to_string(counter_10_5)  + ")";
        // logger::log(logger::INFO) << log << std::endl;

    }

    static void generation_simulation(Client *client, unsigned int thread_id, size_t N_entries, unsigned int step,
                                      double search_rate, std::atomic_size_t *entries_counter) {

        std::map<std::string, int> keyword_cache_time;
        std::map<std::string, int> keyword_update_time;
        std::map<std::string, int> keyword_search_time;

        const std::string kKeywordGroupBase = "Group-";
        const std::string kKeyword10GroupBase = kKeywordGroupBase + "10^";

        constexpr uint32_t max_10_counter = ~0;
        size_t counter = thread_id;
        std::string id_string = std::to_string(thread_id);

        uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0;

        // the longer the list is, the more frequent it's updated
        std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_20, kw_30, kw_60;

        double search_or_update[2] = {search_rate, 1.0 - search_rate};
        double search_level[4] = {1.00, 0.75, 0.5, 0.25};


        bool not_repeat_search = true;
        srand(thread_id);
        int search_time = 0;
        for (size_t i = 0; counter < N_entries;) {

            double r = rand_0_to_1();
            bool is_search = sample(r, search_rate);


            if (!is_search) {// if not a search query

                // prng.GenerateBlock(tmp, sizeof(tmp));
                // std::string ind = /*Util.str2hex*/( std::string((const char*)tmp, ind_len) );


                if (counter_10_1 < max_10_counter) {
                    kw_10_1 = kKeyword10GroupBase + "1_" + id_string + "_" + std::to_string(counter_10_1);

                    keyword_update_time[kw_10_1] = counter_10_1;

                    if ((i + 1) % 10 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_1 << std::endl;
                        }*/
                        counter_10_1++;
                    }
                }
                if (counter_20 < max_10_counter) {
                    kw_20 = kKeywordGroupBase + "20_" + id_string + "_" + std::to_string(counter_20);
                    keyword_update_time[kw_20] = counter_20;
                    if ((i + 1) % 20 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_20 << std::endl;
                        }*/
                        counter_20++;
                    }
                }
                if (counter_30 < max_10_counter) {
                    kw_30 = kKeywordGroupBase + "30_" + id_string + "_" + std::to_string(counter_30);
                    keyword_update_time[kw_30] = counter_30;
                    if ((i + 1) % 30 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_30 << std::endl;
                        }*/
                        counter_30++;
                    }
                }
                if (counter_60 < max_10_counter) {
                    kw_60 = kKeywordGroupBase + "60_" + id_string + "_" + std::to_string(counter_60);
                    keyword_update_time[kw_60] = counter_60;
                    if ((i + 1) % 60 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_60 << std::endl;
                        }*/
                        counter_60++;
                    }
                }
                if (counter_10_2 < max_10_counter) {
                    kw_10_2 = kKeyword10GroupBase + "2_" + id_string + "_" + std::to_string(counter_10_2);
                    keyword_update_time[kw_10_2] = counter_10_2;
                    if ((i + 1) % 100 == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_2 << std::endl;
                        }*/
                        counter_10_2++;
                    }
                }
                if (counter_10_3 < max_10_counter) {
                    kw_10_3 = kKeyword10GroupBase + "3_" + id_string + "_" + std::to_string(counter_10_3);
                    keyword_update_time[kw_10_3] = counter_10_3;
                    if ((i + 1) % ((size_t)(1e3)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_3 << std::endl;
                        }*/
                        counter_10_3++;
                    }
                }
                if (counter_10_4 < max_10_counter) {
                    kw_10_4 = kKeyword10GroupBase + "4_" + id_string + "_" + std::to_string(counter_10_4);
                    keyword_update_time[kw_10_4] = counter_10_4;
                    if ((i + 1) % ((size_t)(1e4)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_4 << std::endl;
                        }*/
                        counter_10_4++;
                    }
                }
                if (counter_10_5 < max_10_counter) {
                    kw_10_5 = kKeyword10GroupBase + "5_" + id_string + "_" + std::to_string(counter_10_5);
                    keyword_update_time[kw_10_5] = counter_10_5;
                    if ((i + 1) % ((size_t)(1e5)) == 0) {
                        /*if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_5 << std::endl;
                        }*/
                        counter_10_5++;
                    }
                }


                (*entries_counter)++;
                if (((*entries_counter) % 100) == 0) {
                    logger::log(logger::INFO) << "Random DB generation: " << ": " << (*entries_counter)
                                              << " entries generated\r" << std::flush;
                }

                // only update counts
                counter += step;
                i++;
                not_repeat_search = true;
            } else if (not_repeat_search) { // generate search
                // perform search query
                double u = rand_0_to_1();
                bool sure_to_search = sample(u, search_level[thread_id % 4]);
                if (sure_to_search) {

                    keyword_cache_time[kw_10_1] = counter_10_1;
                    keyword_cache_time[kw_20] = counter_20;
                    keyword_cache_time[kw_30] = counter_30;
                    keyword_cache_time[kw_60] = counter_60;
                    keyword_cache_time[kw_10_2] = counter_10_2;
                    keyword_cache_time[kw_10_3] = counter_10_3;
                    keyword_cache_time[kw_10_4] = counter_10_4;
                    keyword_cache_time[kw_10_5] = counter_10_5;

                    keyword_search_time[kw_10_1] = keyword_search_time[kw_10_1] + 1;
                    keyword_search_time[kw_20] = keyword_search_time[kw_20] + 1;
                    keyword_search_time[kw_30] = keyword_search_time[kw_30] + 1;
                    keyword_search_time[kw_60] = keyword_search_time[kw_60] + 1;
                    keyword_search_time[kw_10_2] = keyword_search_time[kw_10_2] + 1;
                    keyword_search_time[kw_10_3] = keyword_search_time[kw_10_3] + 1;
                    keyword_search_time[kw_10_4] = keyword_search_time[kw_10_4] + 1;
                    keyword_search_time[kw_10_5] = keyword_search_time[kw_10_5] + 1;
                    // std::string record = kw_10_1+","+kw_10_2+","+kw_10_3+","+kw_10_4+","+kw_10_5+","+kw_20+","+kw_30+","+kw_60;
                    // log_trace(thread_id, i, 1, record); // log for search query
                    search_time++;
                    not_repeat_search = false;

                }// end	else
            }// end if
        } // end for

        logger::log(logger::INFO) << search_time << std::endl;

        //  gRPC for update
        UpdateRequestMessage update_request;

        ClientContext update_context;

        ExecuteStatus update_status;

        std::unique_ptr <RPC::Stub> update_stub_(
                RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));

        std::unique_ptr <ClientWriterInterface<UpdateRequestMessage>> update_writer(
                update_stub_->batch_update(&update_context, &update_status));

        //  gRPC for cache simulation
        CacheRequestMessage cache_request;

        ClientContext cache_context;

        ExecuteStatus cache_status;

        std::unique_ptr <RPC::Stub> cache_stub_(
                RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));

        std::unique_ptr <ClientWriterInterface<CacheRequestMessage>> cache_writer(
                cache_stub_->batch_cache(&cache_context, &cache_status));



        // now begin db and cache generating simulation
        logger::log(logger::INFO) << ">>>> begin simulation..." << std::endl;

        AutoSeededRandomPool prng;

        for (std::map<std::string, int>::iterator it = keyword_update_time.begin();
             it != keyword_update_time.end(); ++it) {
            std::string keyword = it->first;
            int update_time = it->second;
            int search_time = keyword_search_time[keyword];
            int cache_length = keyword_cache_time[keyword];
            int update_after_search = update_time - cache_length;

            client->set_search_time(keyword, search_time);

            int ind_len = AES::BLOCKSIZE / 2; // AES::BLOCKSIZE = 16
            byte tmp[ind_len];

            // process cache
            std::string cache_inds = "";
            for (size_t i = 0; i < cache_length; i++) {
                prng.GenerateBlock(tmp, sizeof(tmp));
                cache_inds += Util::str2hex(std::string((const char *) tmp, ind_len)) + "|";
            }
            logger::log(logger::INFO) << "keyword: " << keyword << " , cache_inds:" << cache_inds << std::endl;

            // upload cache_inds
            if (cache_length != 0) cache_writer->Write(client->gen_cache_request(keyword, cache_inds));

            // process update
            for (size_t i = 0; i < update_after_search; i++) {
                prng.GenerateBlock(tmp, sizeof(tmp));
                std::string ind = std::string((const char *) tmp, ind_len);
                update_writer->Write(client->gen_update_request("1", keyword, ind));
                logger::log(logger::INFO) << "keyword: " << keyword << " , update_after_search:" << update_after_search
                                          << std::endl;
            }// for



        }// for

        logger::log(logger::INFO) << "<<<< end simulation." << std::endl;

        // now tell server we have finished
        update_writer->WritesDone();
        Status status = update_writer->Finish();
        assert(status.ok());

        cache_writer->WritesDone();
        status = cache_writer->Finish();
        assert(status.ok());

    }// generation_simualtion


    void gen_db(Client &client, size_t N_entries, unsigned int n_threads, double search_rate) {
        std::atomic_size_t entries_counter(0);

        // client->start_update_session();

        // unsigned int n_threads = std::thread::hardware_concurrency();
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;

        struct timeval t1, t2;

        gettimeofday(&t1, NULL);

        for (unsigned int i = 0; i < n_threads; i++) {
            threads.push_back(
                    std::thread(generation_trace, &client, i, N_entries, n_threads, search_rate, &entries_counter));
        }

        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }

        gettimeofday(&t2, NULL);

        logger::log(logger::INFO) << "update time: "
                                  << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                  << std::endl;

    } // gen_db

    void gen_simulation(Client &client, size_t N_entries, unsigned int n_threads, double search_rate) {
        std::atomic_size_t entries_counter(0);

        // client->start_update_session();

        // unsigned int n_threads = std::thread::hardware_concurrency();
        std::vector <std::thread> threads;
        // std::mutex rpc_mutex;

        struct timeval t1, t2;

        gettimeofday(&t1, NULL);

        for (unsigned int i = 0; i < n_threads; i++) {
            threads.push_back(std::thread(generation_simulation, &client, i, N_entries, n_threads, search_rate,
                                          &entries_counter));
        }

        for (unsigned int i = 0; i < n_threads; i++) {
            threads[i].join();
        }

        gettimeofday(&t2, NULL);

        logger::log(logger::INFO) << "update time: "
                                  << ((t2.tv_sec - t1.tv_sec) * 1000000.0 + t2.tv_usec - t1.tv_usec) / 1000.0 << " ms"
                                  << std::endl;
        // client->end_update_session();
    } // gen_simulation

}//namespace DistSSE


#endif // DISTSSE_TRACE_H
