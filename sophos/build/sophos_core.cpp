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


#include "sophos_core.hpp"

#include "utils.hpp"
#include "logger.hpp"
#include "thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
namespace sophos {

    const std::string SophosClient::tdp_sk_file__ = "tdp_sk.key";
    const std::string SophosClient::derivation_key_file__ = "derivation_master.key";

size_t TokenHasher::operator()(const update_token_type& ut) const
{
    size_t h = 0;
    for (size_t i = 0; i < kUpdateTokenSize; i++) {
        if (i > 0) {
            h <<= 8;
        }
        h = ut[i] + h;
    }
    return h;
}

SophosClient::SophosClient() :
    k_prf_(), inverse_tdp_()
{
}

SophosClient::SophosClient(const std::string& tdp_private_key, const std::string& derivation_master_key) :
k_prf_(derivation_master_key), inverse_tdp_(tdp_private_key)
{
}

SophosClient::~SophosClient()
{

}

const std::string SophosClient::public_key() const
{
    return inverse_tdp_.public_key();
}

const std::string SophosClient::private_key() const
{
    return inverse_tdp_.private_key();
}

const std::string SophosClient::master_derivation_key() const
{
    return std::string(k_prf_.key().begin(), k_prf_.key().end());
}

const crypto::Prf<kDerivationKeySize>& SophosClient::derivation_prf() const
{
    return k_prf_;
}
const sse::crypto::TdpInverse& SophosClient::inverse_tdp() const
{
    return inverse_tdp_;
}

void SophosClient::write_keys(const std::string& dir_path) const
{
    if (!is_directory(dir_path)) {
        throw std::runtime_error(dir_path + ": not a directory");
    }

    std::string sk_path = dir_path + "/" + tdp_sk_file__;
    std::string master_key_path = dir_path + "/" + derivation_key_file__;

    std::ofstream sk_out(sk_path.c_str());
    if (!sk_out.is_open()) {
        throw std::runtime_error(sk_path + ": unable to write the secret key");
    }

    sk_out << private_key();
    sk_out.close();

    std::ofstream master_key_out(master_key_path.c_str());
    if (!master_key_out.is_open()) {
        throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
    }

    master_key_out << master_derivation_key();
    master_key_out.close();

}

SophosServer::SophosServer(const std::string& db_path, const std::string& tdp_pk) :
edb_(db_path), public_tdp_(tdp_pk, 2*std::thread::hardware_concurrency())
{

}

SophosServer::SophosServer(const std::string& db_path, const size_t tm_setup_size, const std::string& tdp_pk) :
    edb_(db_path), /*edb_(db_path, tm_setup_size),*/
    public_tdp_(tdp_pk, 2*std::thread::hardware_concurrency())
{

}

const std::string SophosServer::public_key() const
{
    return public_tdp_.public_key();
}

std::list<index_type> SophosServer::search(const SearchRequest& req)
{
    std::list<index_type> results;

    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

    if (logger::severity() <= logger::DBG) {

        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    for (size_t i = 0; i < req.add_count; i++) {
        std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        update_token_type ut = derivation_prf.prf(st_string + '0');

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
        }

        bool found = edb_.get(ut,r);

        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }

            r = xor_mask(r, derivation_prf.prf(st_string + '1'));
            results.push_back(r);
        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

        st = public_tdp_.eval(st);
    }

    return results;
}

    void SophosServer::search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
    {
        search_token_type st = req.token;

        auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

            logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
        }

        for (size_t i = 0; i < req.add_count; i++) {
            std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
            index_type r;
            update_token_type ut = derivation_prf.prf(st_string + '0');

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
            }

            bool found = edb_.get(ut,r);

            if (found) {
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                }

                r = xor_mask(r, derivation_prf.prf(st_string + '1'));
                post_callback(r);
            }else{
                logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
            }

            st = public_tdp_.eval(st);
        }
    }


std::list<index_type> SophosServer::search_parallel_full(const SearchRequest& req)
{
    std::list<index_type> results;

    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    ThreadPool prf_pool(1);
    ThreadPool token_map_pool(1);
    ThreadPool decrypt_pool(1);

    auto decrypt_job = [&derivation_prf, &results](const index_type r, const std::string& st_string)
    {
        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
        results.push_back(v);
    };

    auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
    {
        index_type r;

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }

        bool found = edb_.get(token,r);

        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }

            decrypt_pool.enqueue(decrypt_job, r, st_string);

        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

    };


    auto derive_job = [&derivation_prf,&token_map_pool,&lookup_job](const std::string& input_string)
    {
        update_token_type ut = derivation_prf.prf(input_string + '0');

        token_map_pool.enqueue(lookup_job, input_string, ut);

    };

    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto rsa_job = [this, &st, &derive_job, &prf_pool](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            prf_pool.enqueue(derive_job, st_string);
        }

        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);

            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            prf_pool.enqueue(derive_job, st_string);
        }
    };

    std::vector<std::thread> rsa_threads;

    unsigned n_threads = std::thread::hardware_concurrency()-3;

    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, n_threads));
    }

    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads[t].join();
    }

    prf_pool.join();
    token_map_pool.join();


    return results;
}

std::list<index_type> SophosServer::search_parallel(const SearchRequest& req, uint8_t access_threads)
{
    std::list<index_type> results;
    std::mutex res_mutex;

    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    ThreadPool access_pool(access_threads);

    auto access_job = [&derivation_prf, this, &results, &res_mutex, &access_threads](const std::string& st_string)
    {
        update_token_type token = derivation_prf.prf(st_string + '0');

        index_type r;

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }

        bool found = edb_.get(token,r);

        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }
        }else{
//            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));

        if (access_threads > 1) {
            res_mutex.lock();
        }
        results.push_back(v);
        if (access_threads > 1) {
            res_mutex.unlock();
        }
    };



    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto rsa_job = [this, &st, &access_job, &access_pool](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup
            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            access_pool.enqueue(access_job, st_string);
        }

        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);

            std::string st_string(reinterpret_cast<char*>(local_st.data()), local_st.size());
            access_pool.enqueue(access_job, st_string);

        }
    };

    std::vector<std::thread> rsa_threads;

    unsigned n_threads = std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, n_threads));
    }

    for (uint8_t t = 0; t < n_threads; t++) {
        rsa_threads[t].join();
    }

    access_pool.join();

    return results;
}

std::list<index_type> SophosServer::search_parallel_light(const SearchRequest& req, uint8_t threads_count)
{
    assert(threads_count > 0);


    // use one result list per thread so to avoid using locks
    std::list<index_type> *result_lists = new std::list<index_type>[threads_count];

    auto callback = [&result_lists](index_type i, uint8_t thread_id)
    {
        result_lists[thread_id].push_back(i);
    };

    search_parallel_light_callback(req, callback, threads_count);

    // merge the result lists
    std::list<index_type> results(std::move(result_lists[0]));
    for (uint8_t i = 1; i < threads_count; i++) {
        results.splice(results.end(), result_lists[i]);
    }

    delete []  result_lists;

    return results;

}

void SophosServer::search_parallel_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t rsa_thread_count, uint8_t access_thread_count, uint8_t post_thread_count)
{
    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    ThreadPool access_pool(access_thread_count);
    ThreadPool post_pool(post_thread_count);

    auto access_job = [&derivation_prf, this, &post_pool, &post_callback](const search_token_type st, size_t i)
    {
        std::string st_string(reinterpret_cast<const char*>(st.data()), st.size());
        update_token_type token = derivation_prf.prf(st_string + '0');

        index_type r;

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }

        bool found = edb_.get(token,r);

        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }

            index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));

            post_pool.enqueue(post_callback, v);

        }else{
            logger::log(logger::ERROR) << "We were supposed to find a value mapped to key " << hex_string(token);
            logger::log(logger::ERROR) << " (" << i << "-th derived key from search token " << st_string << ")" << std::endl;
        }

    };



    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto rsa_job = [this, &st, &access_job, &access_pool](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup
            access_pool.enqueue(access_job, local_st, index);
        }

        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);

            access_pool.enqueue(access_job, local_st, i);
        }
    };

    std::vector<std::thread> rsa_threads;

//    unsigned n_threads = std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < rsa_thread_count; t++) {
        rsa_threads.push_back(std::thread(rsa_job, t, req.add_count, rsa_thread_count));
    }

    for (uint8_t t = 0; t < rsa_thread_count; t++) {
        rsa_threads[t].join();
    }

    access_pool.join();
    post_pool.join();
}

void SophosServer::search_parallel_light_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t thread_count)
{
    auto aux = [&post_callback](index_type ind, uint8_t i)
    {
        post_callback(ind);
    };
    search_parallel_light_callback(req, aux, thread_count);
}

void SophosServer::search_parallel_light_callback(const SearchRequest& req, std::function<void(index_type, uint8_t)> post_callback, uint8_t thread_count)
{
    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;

        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    auto derive_access = [&derivation_prf, this, &post_callback](const uint8_t t_id, const search_token_type st, size_t i)
    {
        std::string st_string(reinterpret_cast<const char*>(st.data()), st.size());
        update_token_type token = derivation_prf.prf(st_string + '0');

        index_type r;

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }

        bool found = edb_.get(token,r);

        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }

            index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));

            post_callback(v, t_id);

        }else{
//            logger::log(logger::ERROR) << "We were supposed to find a value mapped to key " << hex_string(token);
//            logger::log(logger::ERROR) << " (" << i << "-th derived key from search token " << st_string << ")" << std::endl;
        }

    };



    // the rsa job launched with input index,max computes all the RSA tokens of order i + kN up to max
    auto job = [this, &st, &derivation_prf, &derive_access](const uint8_t index, const size_t max, const uint8_t N)
    {
        search_token_type local_st = st;
        if (index != 0) {
            local_st = public_tdp_.eval(local_st, index);
        }

        if (index < max) {
            // this is a valid search token, we have to derive it and do a lookup

            derive_access(index, local_st, index);
        }

        for (size_t i = index+N; i < max; i+=N) {
            local_st = public_tdp_.eval(local_st, N);

            derive_access(index, local_st, index);
        }
    };

    std::vector<std::thread> rsa_threads;

    //    unsigned n_threads = std::thread::hardware_concurrency()-access_threads;

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads.push_back(std::thread(job, t, req.add_count, thread_count));
    }

    for (uint8_t t = 0; t < thread_count; t++) {
        rsa_threads[t].join();
    }
}

void SophosServer::update(const UpdateRequest& req)
{
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
    }

//    edb_.add(req.token, req.index);
    edb_.put(req.token, req.index);
}

std::ostream& SophosServer::print_stats(std::ostream& out) const
{
//    out << "Number of tokens: " << edb_.size();
//    out << "; Load: " << edb_.load();
//    out << "; Overflow bucket size: " << edb_.overflow_size() << std::endl;

    return out;
}

} // namespace sophos
} // namespace sse
