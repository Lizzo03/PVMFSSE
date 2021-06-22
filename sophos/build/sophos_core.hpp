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

#include "rocksdb_wrapper.hpp"

#include <string>
#include <array>
#include <fstream>
#include <functional>

#include <ssdmap/bucket_map.hpp>
#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
namespace sophos {
        

constexpr size_t kSearchTokenSize = crypto::Tdp::kMessageSize;
constexpr size_t kDerivationKeySize = 16;
constexpr size_t kUpdateTokenSize = 16;

typedef std::array<uint8_t, kSearchTokenSize> search_token_type;
//typedef std::string search_token_type;
typedef std::array<uint8_t, kUpdateTokenSize> update_token_type;
typedef uint64_t index_type;
    
struct TokenHasher
{
public:
    size_t operator()(const update_token_type& ut) const;
};
    
struct SearchRequest
{
    search_token_type   token;
    std::string         derivation_key;
    uint32_t            add_count;
};


struct UpdateRequest
{
    update_token_type   token;
    index_type          index;
};
    
    
class SophosClient {
public:
    SophosClient();
    SophosClient(const std::string& tdp_private_key, const std::string& derivation_master_key);
    virtual ~SophosClient();
    
    virtual size_t keyword_count() const = 0;
    
    const std::string private_key() const;
    const std::string public_key() const;
    const std::string master_derivation_key() const;

    virtual void write_keys(const std::string& dir_path) const;
    
    virtual SearchRequest   search_request(const std::string &keyword) const = 0;
    virtual SearchRequest   search_request_with_counter(const std::string &keyword, const uint32_t kw_counter) const = 0;
    virtual UpdateRequest   update_request(const std::string &keyword, const index_type index) = 0;
    virtual UpdateRequest   update_request_with_counter(const std::string &keyword, const index_type index, uint32_t &kw_counter) = 0;
    
    virtual std::ostream& db_to_json(std::ostream& out) const = 0;
    virtual std::ostream& print_stats(std::ostream& out) const = 0;

    const crypto::Prf<kDerivationKeySize>& derivation_prf() const;
    const sse::crypto::TdpInverse& inverse_tdp() const;

    static const std::string tdp_sk_file__;
    static const std::string derivation_key_file__;

private:
    crypto::Prf<kDerivationKeySize> k_prf_;
    sse::crypto::TdpInverse inverse_tdp_;
};

class SophosServer {
public:
    
    
    
    SophosServer(const std::string& db_path, const std::string& tdp_pk);
    SophosServer(const std::string& db_path, const size_t tm_setup_size, const std::string& tdp_pk);
    
    const std::string public_key() const;

    std::list<index_type> search(const SearchRequest& req);
    void search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback);
    
    std::list<index_type> search_parallel_full(const SearchRequest& req);
    std::list<index_type> search_parallel(const SearchRequest& req, uint8_t access_threads);
    std::list<index_type> search_parallel_light(const SearchRequest& req, uint8_t thread_count);

    void search_parallel_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t rsa_thread_count, uint8_t access_thread_count, uint8_t post_thread_count);
    void search_parallel_light_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t thread_count);
    void search_parallel_light_callback(const SearchRequest& req, std::function<void(index_type, uint8_t)> post_callback, uint8_t thread_count);

    void update(const UpdateRequest& req);
    
    std::ostream& print_stats(std::ostream& out) const;
private:
//    ssdmap::bucket_map<update_token_type, index_type, TokenHasher> edb_;
    RockDBWrapper edb_;
    
    sse::crypto::TdpMultPool public_tdp_;
};

} // namespace sophos
} // namespace sse
