#include "DistSSE.client.h"
#include "DistSSE.db_generator.h"

#include "logger.h"

using DistSSE::SearchRequestMessage;

int main(int argc, char **argv) {
    DistSSE::logger::set_severity(DistSSE::logger::INFO);
    //DistSSE::logger::log(DistSSE::logger::INFO) << " client test :  "<< std::endl;
    //DistSSE::logger::log_benchmark() << "client to file" <<std::endl;
    // Instantiate the client and channel isn't authenticated
    DistSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()),
                           std::string(argv[1]));

    if(argc == 2){
        DistSSE::gen_db_3(client);
        return 0;
    }

    if(argc == 3){
        int type = atoi(argv[2]);
        if(type == 1){
            client.update("1","keyword","ind");
        }else if(type == 2){
            client.batch_update("keyword", 3);
        }else{
            client.search("keyword");
        }
        return 0;
    }


    if (argc < 7) {
        std::cerr << "argc error" << std::endl;
        exit(-1);
    }
    size_t N_entry = atoi(argv[2]);
    std::string w = std::string(argv[3]);
    int flag = atoi(argv[4]);
    int threads_num = atoi(argv[5]);
    std::cout << "update begin..." << std::endl;
    //if (flag == 1) DistSSE::generate_trace(&client, N_entry);
    if (flag == 1){
        DistSSE::gen_db(client, N_entry, threads_num);
        std::cout << "update done." << std::endl;
        client.search(w);
        std::cout << "search done: " << std::endl;
    }else if(flag == 2){
        std::string logFileName = argv[6];
        DistSSE::logger::set_benchmark_file(logFileName);
        DistSSE::gen_db_2(client, N_entry, w, threads_num);
        std::cout << "update done." << std::endl;
    }else if(flag == 3){
        client.search(w);
        std::cout << "search done: " << std::endl;
    }else if(flag == 4){
        std::string logFileName = argv[6];
        DistSSE::logger::set_benchmark_file(logFileName);
        DistSSE::gen_db_4(client, N_entry, threads_num);
        std::cout << "update done." << std::endl;
    }else{

    }
    return 0;
}

