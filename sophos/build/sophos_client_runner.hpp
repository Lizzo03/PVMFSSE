//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#pragma once

#include "sophos_core.hpp"

#include "sophos.grpc.pb.h"

#include <memory>
#include <thread>
#include <atomic>
#include <grpc++/channel.h>

#include <mutex>
#include <condition_variable>

namespace sse {
namespace sophos {

class SophosClientRunner {
public:
    SophosClientRunner(const std::string& address, const std::string& path, size_t setup_size = 1e5, uint32_t n_keywords = 1e4);
    SophosClientRunner(const std::string& address, const std::string& db_path, const std::string& json_path);
    ~SophosClientRunner();
    
    const SophosClient& client() const;
    
    std::list<uint64_t> search(const std::string& keyword, std::function<void(uint64_t)> receive_callback = NULL) const;
    std::list<uint64_t> search_with_counter(const std::string& keyword, uint32_t kw_counter, std::function<void(uint64_t)> receive_callback = NULL) const;    
    void update(const std::string& keyword, uint64_t index);
    void update_with_counter(const std::string& keyword, uint64_t index, uint32_t &counter); //added by xiangfu
    
    void async_update(const std::string& keyword, uint64_t index);

    void start_update_session();
    void end_update_session();
    void update_in_session(const std::string& keyword, uint64_t index);

    void wait_updates_completion();
    
    bool load_inverted_index(const std::string& path);

    bool output_db(const std::string& out_path);
    std::ostream& print_stats(std::ostream& out) const;

    void random_search() const;
    void search_benchmark(size_t n_bench) const;

    void trace_evaluation(uint32_t thread_num);

private:
    void update_completion_loop();
    
    bool send_setup(const size_t setup_size) const;
    
    std::unique_ptr<sophos::Sophos::Stub> stub_;
    std::unique_ptr<SophosClient> client_;
    
    struct {
        std::unique_ptr<grpc::ClientWriter<sophos::UpdateRequestMessage>> writer;
        std::unique_ptr<::grpc::ClientContext> context;
        ::google::protobuf::Empty response;
        
        std::mutex mtx;
        bool is_up;
    } bulk_update_state_;
//    std::unique_ptr<grpc::ClientWriter<sophos::UpdateRequestMessage>> bulk_update_writer_;
    
    grpc::CompletionQueue update_cq_;

    std::atomic_size_t update_launched_count_, update_completed_count_;
    std::thread* update_completion_thread_;
    std::mutex update_completion_mtx_;
    std::condition_variable update_completion_cv_;
    bool stop_update_completion_thread_;

    std::mutex update_mtx_;
};

SearchRequestMessage request_to_message(const SearchRequest& req);
UpdateRequestMessage request_to_message(const UpdateRequest& req);

} // namespace sophos
} // namespace sse
