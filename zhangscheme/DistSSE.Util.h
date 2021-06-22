/*
 * Created by Xiangfu Song on 10/21/2016.
 * Email: bintasong@gmail.com
 * 
 */
#ifndef DISTSSE_UTIL_H
#define DISTSSE_UTIL_H

#include <random>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cassert>
#include <memory>
#include <string>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <stdexcept>
#include <csignal>
#include <unordered_set>
#include <unistd.h>

#include <sys/time.h>

#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>


#include <thread>

#include "DistSSE.string_append_operator.h"


#define MAX_W_LEN 16
#define MAX_OP_LEN 3
#define MAX_IND_LEN 20
#define MAX_NODE_LEN 4
#define MAX_UPDATE_LEN 6
#define MAX_ST_LEN 32 //ST = W||NODE||UPDATE = 26 < 32 
#define AES128_KEY_LEN 16
#define LABEL_LEN 48//(MAX_IND_LEN + MAX_W_LEN)  LABEL = IND||W = 36 < 48
#define UT_LEN 32
#define VALUE_LEN (MAX_IND_LEN + MAX_OP_LEN + MAX_ST_LEN) // VALUE = IND||OP||ST = 55

#define random(x) (rand()%x)

// 用来生成kw
extern CryptoPP::byte k_s[17];
extern CryptoPP::byte iv_s[17];

// 用来生成加密label
extern CryptoPP::byte k_l[17];
extern CryptoPP::byte iv_l[17];

// 用来生成搜索token
extern CryptoPP::byte k_st[17];
extern CryptoPP::byte iv_st[17];

// 系统参数
extern int max_keyword_length;
extern int max_nodes_number;

namespace DistSSE {

    class Util {

    public:
        static std::string H1(const std::string message);

        static std::string H2(const std::string message);

        static std::string padding(const std::string str);

        static std::string padding(const std::string str, size_t len);

        static std::string remove_padding(const std::string str);

        static std::string Xor(const std::string s1, const std::string s2);

        static void split(const std::string &s, char delim, std::vector <std::string> &elems);

        static void split(const std::string &s, char delim, std::unordered_set <std::string> &ID);

        static std::string dec_token(const void *key, int key_len, const void *iv, std::string enc_token);

        static std::string Enc(const void *key, int key_len, const std::string plain);

        static std::string Dec(const void *key, int key_len, const std::string cipher);

        static std::string str2hex(const std::string &input);

        static std::string hex2str(const std::string &input);

        static void set_db_common_options(rocksdb::Options &options);
    };

}// namespace DistSSE

#endif //DISTSSE_UTIL_H
