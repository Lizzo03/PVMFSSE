//
// ssdmap - Implementation of a disk-resident map designed for SSDs.
// Copyright (C) 2016 Raphael Bost
//
// This file is part of ssdmap.
//
// ssdmap is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ssdmap is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ssdmap.  If not, see <http://www.gnu.org/licenses/>.
//


/** @file bucket_map.hpp
 * @brief Header that defines the bucket_map container class.
 *
 *
 */



#pragma once

#include "bucket_array.hpp"
#include "mmap_util.h"

#include <utility>
#include <unordered_map>
#include <map>
#include <vector>
#include <list>
#include <string>
#include <sstream>
#include <random>

#include <cmath>
#include <cstring>
#include <cassert>
#include <sys/stat.h>

namespace ssdmap {
    
   
constexpr float kBucketMapResizeThresholdLoad = 0.95; /**< @brief Maximum load of the map. */
constexpr size_t kBucketMapResizeMaxOverflowSize = 5e5; /**< @brief Maximum size of the overflow bucket. */
constexpr float kBucketMapResizeMaxOverflowRatio = 0.1; /**< @brief Maximum value of the ratio between the size of the overflow bucket and the size of the map. */
constexpr size_t kBucketMapResizeStepIterations = 4; /**< @brief Number of buckets rebuilt at every insertion during the rebuild phase.  */

constexpr size_t kPageSize = 512; /**< @brief Size (in bytes) of a bucket. */

    
/** @class bucket_map
 *  @brief An on-disk associative map implementation allowing for fast retrieval
 and efficient updates.
 *
 *  In a bucket_map, the key value is used to uniquely identify the elements. 
 *  The elements are put in 2^mask_size buckets: the key-value pair (k,v) is put in bucket truncate( h(k), mask_size) (the last mask_size bits of h(k)).
 *  Inside each bucket, the elements are organized as an unordered list. 
 *  When a bucket is full, any additionally inserted element is put in an overflow bucket.
 *  Deletion are not supported.
 *
 *  bucket_map are stored on disk, in a directory specified in the constructor.
 *  The organisation of the directory is as follows: a metadata.bin files contains all the necessary metadata needed by the data structure, such as the overflow bucket size, the number of inserted elements, the mask size, or a flag signaling if the structure is resizing; an overflow.bin file encodes the overflow bucket (if non empty), and data.* files encode the data structure itself.
 *  No integrity check is performed when reading from an input directory.
 *
 *  @tparam Key     Type of the key values. Each element in a bucket_map is uniquely identified by its key value.
 Aliased as member type bucket_map::key_type.
 *
 *  @tparam T       Type of the mapped value. Each element in an bucket_map is used to store some data as its mapped value.
 Aliased as member type bucket_map::mapped_type. Note that this is not the same as bucket_map::value_type (see below).
 *
 *  @tparam Hash    A unary function object type that takes an object of type key type as argument and returns a unique value of type size_t based on it. This can either be a class implementing a function call operator or a pointer to a function (see constructor for an example). This defaults to hash<Key>, which returns a hash value with a probability of collision approaching 1.0/std::numeric_limits<size_t>::max().
 The unordered_map object uses the hash values returned by this function to organize its elements internally, speeding up the process of locating individual elements.
 Aliased as member type bucket_map::hasher.
 *
 *  @tparam Pred    A binary predicate that takes two arguments of the key type and returns a bool. The expression pred(a,b), where pred is an object of this type and a and b are key values, shall return true if a is to be considered equivalent to b. This can either be a class implementing a function call operator or a pointer to a function (see constructor for an example). This defaults to equal_to<Key>, which returns the same as applying the equal-to operator (a==b).
 The unordered_map object uses this expression to determine whether two element keys are equivalent. No two elements in an unordered_map container can have keys that yield true using this predicate.
 Aliased as member type unordered_map::key_equal.

 */
    
template <class Key, class T, class Hash = std::hash<Key>, class Pred = std::equal_to<Key>>
class bucket_map {
public:
    typedef Key                                                        key_type;        /**< @brief The first template parameter (Key)	*/
    typedef T                                                          mapped_type;     /**< @brief The second template parameter (T)	*/
    typedef Hash                                                       hasher;          /**< @brief The third template parameter (Hash)	*/
    typedef Pred                                                       key_equal;       /**< @brief The fourth template parameter (Pred)*/
    typedef std::pair<const key_type, mapped_type>                     value_type;      /**< @brief pair<const key_type,mapped_type>	*/
    typedef value_type&                                                reference;       /**< @brief value_type&	*/
    typedef const value_type&                                          const_reference; /**< @brief const value_type&	*/

    typedef size_t          size_type;
    typedef ptrdiff_t       difference_type;
    
    
    typedef std::pair<const key_type, mapped_type>                        bucket_value_type;
    typedef bucket_array<bucket_value_type>                         bucket_array_type;
    typedef typename bucket_array_type::bucket_type                 bucket_type;
    
    typedef std::unordered_map<size_t, value_type>                  overflow_submap_type;
    typedef std::unordered_map<size_t, overflow_submap_type>           overflow_map_type;
    
private:
    overflow_map_type overflow_map_;
    
    std::vector<std::pair<bucket_array_type, mmap_st> > bucket_arrays_;
    
    
    uint8_t mask_size_;
    uint8_t original_mask_size_;
    
    // where to store the files
    std::string base_filename_;
    
    // to compute load
    size_t e_count_;
    size_t bucket_space_;
    size_t overflow_count_;
    
    // resize management
    bool is_resizing_;
    size_t resize_counter_;
    
    // hash function and equality predicate
    hasher hf_;
    key_equal eql_;
    
    typedef struct
    {
        uint8_t original_mask_size;
        uint8_t bucket_arrays_count;
        bool is_resizing;
        size_t resize_counter;
        size_t e_count;
        size_t overflow_count;
    } metadata_type;

public:
    
    class const_iterator /**< @brief Constant iterator over the map's elements */
    {
    private:
        const bucket_map          *map_;
        size_type                 array_index_;
        
        typename bucket_array_type::const_iterator      ba_it_;
        
        typedef     std::forward_iterator_tag   iterator_category;
        
        bool is_iterating_overflow_map_;
        typename overflow_map_type::const_iterator      om_it_;
        typename overflow_submap_type::const_iterator   sub_om_it_;
        
        void increment()
        {
            if (is_iterating_overflow_map_) {
                
                if(sub_om_it_ != om_it_->second.end()){
                    sub_om_it_++;
                }else{
                    return;
                }
                
                if(sub_om_it_ == om_it_->second.end())
                {
                    om_it_++;
                    if (om_it_ != map_->overflow_map_.end()) {
                        sub_om_it_ = om_it_->second.begin();
                    }
                }
            }else{
                ba_it_++;
                
                reach_next();
            }
        }
        
    public:
        const_iterator(const bucket_map* m, size_t ai)
        : map_(m), array_index_(ai), is_iterating_overflow_map_(false)
        {
            if(ai < map_->arrays_count())
            {
                ba_it_ = map_->get_bucket_array(ai).begin();
            }
        }

        const_iterator(const bucket_map* m, size_t ai, bool point_end)
        : map_(m), array_index_(ai), is_iterating_overflow_map_(false)
        {
            if(point_end)
            {
                is_iterating_overflow_map_ = true;
                om_it_ = map_->overflow_map_.end();
            }else{
                if(ai < map_->arrays_count())
                {
                    ba_it_ = map_->get_bucket_array(ai).begin();
                }
            }
        }

        const_iterator& operator++() //prefix increment
        {
            increment();
            
            return (*this);
        }
        
        const_iterator operator++(int) //postfix increment
        {
            const_iterator cpy(*this);
            
            increment();
            
            return cpy;
        }
        
        const_reference operator*() const
        {
            if(is_iterating_overflow_map_)
                return sub_om_it_->second;
            
            return ba_it_.operator*();
        }

        const value_type* operator->() const
        {
            if(is_iterating_overflow_map_)
                return &(sub_om_it_->second);
            
            return ba_it_.operator->();
        }

        // no operator->():
        // it is not possible to cast a reference/pointer to pair<Key, Value> into pair<const Key, Value>
        // the only possible solution would be to create temporary objects, and this is bad ...
        // also, in bucket_array, it is not possible to use pair<const Key, Value> as the value type without using non trivial hacks
        
        const_iterator& reach_next()
        {
            if (ba_it_ == map_->get_bucket_array(array_index_).end()) {
                array_index_++;
                
                while(array_index_ < map_->arrays_count())
                {
                    ba_it_ = map_->get_bucket_array(array_index_).begin();
                    
                    if (ba_it_ == map_->get_bucket_array(array_index_).end()) {
                        array_index_++;
                    }else{
                        break;
                    }
                }
                
                if (array_index_ == map_->arrays_count())
                {
                    is_iterating_overflow_map_ = true;
                    om_it_ = map_->overflow_map_.begin();
                    if (om_it_ != map_->overflow_map_.end()) {
                        sub_om_it_ = om_it_->second.begin();
                    }
                }

            }
            return (*this);
        }
        
        friend bool operator==(const const_iterator& a, const const_iterator& b)
        {
            if(a.map_ != b.map_)
                return false;
            
            if (a.is_iterating_overflow_map_ != b.is_iterating_overflow_map_) {
                return false;
            }
            
            if (a.is_iterating_overflow_map_ == true)
            {
                if (a.om_it_ != b.om_it_)
                {
                    return false;
                }
                if (a.om_it_ == a.map_->get_overflow_map().end()) {
                    return true;
                }
                    
                    
                return (a.sub_om_it_ == b.sub_om_it_);
            }
            
            if (a.array_index_ != b.array_index_) {
                return false;
            }
            
            if (a.array_index_ == a.map_->arrays_count()) // we are at the end
                return true;
            

            return (a.ba_it_ == b.ba_it_);
        }
        friend bool operator!=(const const_iterator& a, const const_iterator& b)
        {
            return !(a == b);
        }
    };
    
    friend const_iterator;
    
    /** 
     *  @brief Constructor
     *
     *  @param path         The path to the directory where the map will be stored.
     *  @param setup_size   The initial size of the map.
     *  @param hf           Hasher function object. A hasher is a function that returns an integral value based on the container object key passed to it as argument.
     Member type hasher is defined in bucket_map as an alias of its third template parameter (Hash).
     *  @param eql          Comparison function object, that returns true if the two container object keys passed as arguments are to be considered equal.
     Member type key_equal is defined in bucket_map as an alias of its fourth template parameter (Pred).
     *
     *  If a valid input directory is given by the constructor, the data structure will be initialized from its content.
     *  Otherwise, a new structure will be initialized, such that it is able to contain @a setup_size elements, and will be stored at @a path.
     *
     *  @exception std::runtime_error The input path is invalid.
     */
    bucket_map(const std::string &path, const size_type setup_size, const hasher& hf = hasher(),
               const key_equal& eql = key_equal())
    : overflow_map_(), bucket_arrays_(), base_filename_(path), e_count_(0), overflow_count_(0),  is_resizing_(false), hf_(hf), eql_(eql)
    {

        // check is there already is a directory at path
        struct stat buffer;
        if(stat (base_filename_.data(), &buffer) == 0) // there is something at path
        {
            if (!S_ISDIR(buffer.st_mode)) {
                throw std::runtime_error("bucket_map constructor: Invalid path. " + path + " is not a directory");
            }
            
            init_from_file();
        }else{
            // create a new directory
            if (mkdir(base_filename_.data(),(mode_t)0700) != 0) {
                throw std::runtime_error("bucket_map constructor: Unable to create the data directory");
            }
            
            
            size_t b_size = bucket_array_type::optimal_bucket_size(kPageSize);
            float target_load = 0.90;
            size_t N;
            
            if(target_load*b_size >= setup_size)
            {
                original_mask_size_ = 1;
            }else{
                float f =setup_size/(target_load*b_size);
                original_mask_size_ = ceilf(log2f(f));
            }
            
            mask_size_ = original_mask_size_;
            N = 1 << mask_size_;

            size_t length = N  * kPageSize;
            
            std::ostringstream string_stream;
            string_stream << base_filename_ << "/data." << std::dec << 0;
            
            mmap_st mmap = create_mmap(string_stream.str().data(),length);
            
            bucket_arrays_.push_back(std::make_pair(bucket_array_type(mmap.mmap_addr, N, kPageSize), mmap));
            bucket_space_ = bucket_arrays_[0].first.bucket_size() * bucket_arrays_[0].first.bucket_count();
        }
    }
    

    /**
     *  @brief Constructor
     *
     *  @param path         The path to the directory where the map is stored.
     *  @param hf           Hasher function object. A hasher is a function that returns an integral value based on the container object key passed to it as argument.
     Member type hasher is defined in bucket_map as an alias of its third template parameter (Hash).
     *  @param eql          Comparison function object, that returns true if the two container object keys passed as arguments are to be considered equal.
     Member type key_equal is defined in bucket_map as an alias of its fourth template parameter (Pred).
     *
     *  This constructor initializes the container from the data stored at @a path. If no valid directory is found, an exception is raised.
     *
     *  @exception std::runtime_error The input path is invalid.
     */
    bucket_map(const std::string &path, const hasher& hf = hasher(),
               const key_equal& eql = key_equal())
    : overflow_map_(), bucket_arrays_(), base_filename_(path), e_count_(0), overflow_count_(0),  is_resizing_(false), hf_(hf), eql_(eql)
    {
        
        // check is there already is a directory at path
        struct stat buffer;
        if(stat (base_filename_.data(), &buffer) == 0) // there is something at path
        {
            if (!S_ISDIR(buffer.st_mode)) {
                throw std::runtime_error("bucket_map constructor: Invalid path. " + path + " is not a directory");
            }
            
            init_from_file();
        }else{
            // throw an error, we were suppose to find a path
            throw std::runtime_error("bucket_map constructor: " + path + ": no such file or directory");
        }
    }
    

    /**
     *  @brief Destructor
     *
     *  The destructor also flushes the data structure to the disk,and this may take some time.
     */
    
    ~bucket_map()
    {
        flush();
    }
    
    /**
     *  @brief Return container size.
     *
     *  Returns the number of elements in the bucket_map container.
     *
     *  @return The number of elements in the container.
     */
    inline size_t size() const
    {
        return e_count_;
    }
    
    /**
     *  @brief Returns iterator to beginning.
     *
     *  Returns an iterator pointing to first element in the bucket_map container.
     *
     *  @return An iterator to the first element in the container.
     */
    inline const_iterator begin() const
    {
        return const_iterator(this, 0).reach_next();
    }
    
    /**
     *  @brief Returns iterator to end.
     *
     *  Returns an iterator pointing to past-the-end element in the bucket_map container.
     *
     *  @return An iterator to the element past-the-end element in the container.
     */
    inline const_iterator end() const
    {
        return const_iterator(this, bucket_arrays_.size(), true);
    }
    
    /**
     *  @brief Returns a random element.
     *
     *  Returns a random element of the bucket_map container.
     *
     *  @return A random element in the container.
     */
   
    const_reference random_element() const
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, (int)((1<<mask_size_) + resize_counter_-1));
        size_t rnd;
        
        while(true)
        {
            rnd = dis(gen);

            auto b = get_bucket(bucket_coordinates(rnd));
            size_t s = b.size();
            if(s > 0)
            {
                std::uniform_int_distribution<> loc_dis(0, (int)(s-1));
                size_t c = loc_dis(gen);
                return *(b.begin()+c);
            }
        }
//        auto pos_pair = bucket_coordinates(rnd);
//        get_bucket(pos_pair.first, pos_pair.second);
    }
    
    /**
     *  @brief Return the total number of elements that can be holded in the buckets.
     *
     *  Returns the sum of the bucket sizes.
     *
     *  @return The total number of elements that can be holded in the buckets.
     */
    inline size_t bucket_space() const
    {
        return bucket_space_;
    }
    
    
    /**
     *  @brief Return container load.
     *
     *  Returns the load of the bucket_map container defined as the ratio between the number of elements of the container, and the maximum number of elements is can contain (without accounting for the overflow bucket).
     *
     *  @return The load of the container.
     */
    inline float load() const
    {
        return ((float)e_count_)/(bucket_space_);
    }
    
    /**
     *  @brief Return overflow bucket size.
     *
     *  Returns the number of elements in the bucket_map overflow bucket.
     *
     *  @return The number of elements in the overflow bucket.
     */

    inline size_t overflow_size() const
    {
        return overflow_count_;
    }
    
    /**
     *  @brief Return container overflow ration.
     *
     *  Returns the overflow ration of the bucket_map container defined as the ratio between the number of elements in the overflow bucket, and the number of elements in the container.
     *
     *  @return The overflow ration of the container.
     */

    inline float overflow_ratio() const
    {
        return ((float)overflow_count_)/(e_count_);
    }
    
    //@{
    /**
     *  @brief Access element
     *
     *  Returns a reference to the mapped value of the element identified with key @a key.
     *  If @a key does not match the key of any element in the container, the function throws an out_of_range exception.
     *
     *  @param[in]  key     Key value of the element whose mapped value is accessed.
     Member type key_type is the type of the keys for the elements in the container, defined in bucket_map as an alias of its first template parameter (Key).
     *
     *  @return     A reference to the mapped value of the element with a key value equivalent to @a key.
     *              If the map object is const-qualified, the function returns a reference to const mapped_type. Otherwise, it returns a reference to mapped_type.
     *              Member type mapped_type is the type to the mapped values in the container, i.e. an alias of its second template parameter (T).
     *
     *  @exception std::out_of_range @a key is not the key of an element in the map.
     */

    mapped_type& at(key_type key)
    {
        size_t h = hf_(key);
        
        // first, look if it is not in the overflow map
        
        try {
            return at_overflow_bucket(h);
        } catch (std::out_of_range &e) {
            
        
        
        
        // otherwise, get the bucket index
        
        // get the appropriate coordinates
        std::pair<uint8_t, size_t> coords = bucket_coordinates(h);
        
        // get the bucket and prefetch it
        auto bucket = get_bucket(coords);
        //        bucket.prefetch();
        
        // scan throught the bucket to find the element
        for (auto it = bucket.begin(); it != bucket.end(); ++it) {
            if(eql_(it->first, key))
            {
                return it->second;
            }
        }
        
        throw std::out_of_range("Key not found");

        }

    }

    const mapped_type& at(key_type key) const
    {
        size_t h = hf_(key);
        
        // first, look if it is not in the overflow map
        
        try {
            return at_overflow_bucket(h);
        } catch (std::out_of_range &e) {
            
            
            
            
            // otherwise, get the bucket index
            
            // get the appropriate coordinates
            std::pair<uint8_t, size_t> coords = bucket_coordinates(h);
            
            // get the bucket and prefetch it
            auto bucket = get_bucket(coords);
            //        bucket.prefetch();
            
            // scan throught the bucket to find the element
            for (auto it = bucket.begin(); it != bucket.end(); ++it) {
                if(eql_(it->first, key))
                {
                    return it->second;
                }
            }
            
            throw std::out_of_range("Key not found");
            
        }
    }
    //@}

    /**
     *  @brief Access element
     *
     * Retrieves the element with key @a key, puts it in @a v and return true if found, and just returns false otherwise.
     *
     *  @param[in]  key     Key to be searched for.
     Member type key_type is the type of the keys for the elements in the container, defined in bucket_map as an alias of its first template parameter (Key).
     *  @param[out] v       A mapped_type object, defined in bucket_map as an alias of its second template parameter (Value).
     If @a key is found, the mapped value will be put in @a v.
     
     *  @retval true    if @a key was found
     *  @retval false   if @a key was not found
     
     */
    bool get(key_type key, mapped_type& v) const
    {
        try {
            v = at(key);
            return true;
        } catch (std::out_of_range &e) {
            return false;
        }
    }
    
    /**
     *  @brief Insert element
     *
     *  Add the element with key @a key and value @a v in the data structure.
     *
     *  @param[in]  key     Key of the element to be inserted.
     Member type key_type is the type of the keys for the elements in the container, defined in bucket_map as an alias of its first template parameter (Key).
     *  @param[in] v        Value of the element to be inserted. A mapped_type object, defined in bucket_map as an alias of its second template parameter (Value).
     */
    void add(key_type key, const mapped_type& v)
    {
        value_type value(key,v);
        
        // get the bucket index
        size_t h = hf_(key);
        
        // get the appropriate coordinates
        std::pair<uint8_t, size_t> coords = bucket_coordinates(h);
        
        // try to append the value to the bucket
        auto bucket = get_bucket(coords);
        
        bool success = bucket.append(value);
        
        if (!success) {
            // add to the overflow bucket
            append_overflow_bucket(h, value);
            
            
            //            std::cout << "Full bucket. " << size() << " elements (load factor " << load() << ")\n size of overflow bucket: " << overflow_size() << ", overflow proportion: " << overflow_ratio() << "\n" << std::endl;
        }
        
        e_count_++;
        
        if (is_resizing_) {
            online_resize();
        }else{
            if (should_resize()) {
                start_resize();
            }
        }
        
    }

    /**
     *  @brief Flush the container to disk.
     *
     *  Writes the content of the container, with its metadata to disk, in the directory specified by the constructor.
     *
     */

    void flush() const
    {
        // flush the data to the disk
        
        // start by syncing the bucket arrays
        // do it asynchronously for now
        for (auto it = bucket_arrays_.rbegin(); it != bucket_arrays_.rend(); ++it) {
            flush_mmap(it->second,ASYNC_FLAG);
        }
        
        // create a new memory map for the overflow bucket
        typedef std::pair<size_t, std::pair<size_t,value_type>> pair_type;
        
        std::string overflow_temp_path = base_filename_ + "/overflow.tmp";
        
        if(overflow_count_ > 0){
            mmap_st over_mmap = create_mmap(overflow_temp_path.data(), overflow_count_*sizeof(pair_type));
            
            
            pair_type* elt_ptr = (pair_type*) over_mmap.mmap_addr;
            size_t i = 0;
            
            for (auto &sub_map : overflow_map_) {
                // submap is a map
                
                for (auto &x : sub_map.second) {
                    pair_type tmp = std::make_pair(sub_map.first, x);
                    memcpy(elt_ptr+i, &tmp, sizeof(pair_type));
                    i++;
                }
            }
            
            // flush it to the disk
            close_mmap(over_mmap);
        }
        // erase the old overflow file and replace it by the temp file
        std::string overflow_path = base_filename_ + "/overflow.bin";
        remove(overflow_path.data());
        
        if(overflow_count_ > 0){
            if (rename(overflow_temp_path.data(), overflow_path.data()) != 0) {
                throw std::runtime_error("Unable to rename overflow.tmp to overflow.bin");
            }
        }
        
        std::string meta_path = base_filename_ + "/meta.bin";
        mmap_st meta_mmap = create_mmap(meta_path.data(), sizeof(metadata_type));
        metadata_type *meta_ptr = (metadata_type *)meta_mmap.mmap_addr;
        
        meta_ptr->original_mask_size = original_mask_size_;
        meta_ptr->is_resizing = is_resizing_;
        meta_ptr->resize_counter = resize_counter_;
        meta_ptr->overflow_count = overflow_count_;
        meta_ptr->e_count = e_count_;
        meta_ptr->bucket_arrays_count = bucket_arrays_.size();
        
        close_mmap(meta_mmap);
        
        for (auto it = bucket_arrays_.rbegin(); it != bucket_arrays_.rend(); ++it) {
            close_mmap(it->second);
        }
    }
    
    /**
     *  @brief Start the online resizing process.
     *
     *  Initiates the online resizing by doubling the number of buckets, and setting the necessary flags so that, at every insertion of a new element, kBucketMapResizeStepIterations buckets are splitted in two according to the hashed key value of the contained elements.
     */
    void start_resize()
    {
        if (is_resizing_) {
            // Useless call
            return;
        }
        
        //        std::cout << "Start resizing!" << std::endl;
        
        // create a new bucket_array of double the size of the previous one
        
        size_t ba_count = bucket_arrays_.size();
        
        size_t N = 1 << (mask_size_);
        
        size_t length = N  * kPageSize;
        
        std::ostringstream string_stream;
        string_stream << base_filename_ << "/data." << std::dec << ba_count;
        
        mmap_st mmap = create_mmap(string_stream.str().data(),length);
        bucket_arrays_.push_back(std::make_pair(bucket_array_type(mmap.mmap_addr, N, kPageSize), mmap));
        
        resize_counter_ = 0;
        is_resizing_ = true;
    }
    
    /**
     *  @brief   Resize the container.
     * 
     *  Resizes the container by doubling the number of buckets, and moving the containers elements in the right bucket.
     *  If the container already was resizing online, this finishes the resizing process.
     */
    void full_resize()
    {
        if(!is_resizing_)
        {
            start_resize();
        }
        
        for (; is_resizing_; ) {
            resize_step();
        }
    }

    /**
     *  @brief   Return the overflow map.
     *
     *  Getter of the overflow map.
     *
     *  @return A const reference to the overflow map.
     */
    const overflow_map_type& get_overflow_map() const
    {
        return overflow_map_;
    }
    
    size_t arrays_count() const
    {
        return bucket_arrays_.size();
    }

private:
    inline std::pair<uint8_t, size_t> bucket_coordinates(size_t h) const
    {
        if (is_resizing_) {
            // we must be careful here
            // the coordinates depend on the value of resize_counter_
            // if h & (1 << mask_size_)-1 is less than resize_counter_, it means that the
            // bucket, before rebuild, was splitted
            // otherwise, do as before
            size_t masked_h = (h & ((1 << mask_size_)-1));
            if (masked_h < resize_counter_) {
                // if the mask_size_-th bit is 0, do as before,
                // otherwise, we know that the bucket is in the last array
                
                if ((h & ((1 << mask_size_))) != 0) {
                    return std::make_pair(mask_size_- original_mask_size_+1, masked_h);
                }
            }
        }
        h &= (1 << mask_size_)-1;

        uint8_t c = mask_size_-1;
        size_t mask = (1 << c);
        
        for (; c >= original_mask_size_; c--, mask >>= 1) { // mask = 2^c
            if ((mask & h) != 0) {
                return std::make_pair(c - original_mask_size_+1, h ^ mask);
            }
        }
        
        return std::make_pair(0, h);
    }
    
    inline size_t get_overflow_bucket_index(size_t h) const
    {
        size_t index = (h&((1 << mask_size_)-1));
        
        if (is_resizing_) {
            // we must be careful here
            // the coordinates depend on the value of resize_counter_
            // if index is less than resize_counter_, it means that the
            // bucket, before rebuild, was splitted
            // otherwise, do as before
            if (index < resize_counter_) {
                // if the mask_size_-th bit is 0, do as before,
                // otherwise, recompute the index accordingly
                
                if ((h & ((1 << mask_size_))) != 0) {
                    return (h&((1 << (mask_size_+1))-1));
                }
            }
        }

        return index;
    }
    
    inline bucket_type get_bucket(uint8_t ba_index, size_t b_pos)
    {
        if (ba_index >= bucket_arrays_.size()) {
            throw std::out_of_range("bucket_map::get_bucket");
        }
        
        return bucket_arrays_[ba_index].first.bucket(b_pos);
    }
    
    inline const bucket_type get_bucket(uint8_t ba_index, size_t b_pos) const
    {
        if (ba_index >= bucket_arrays_.size()) {
            throw std::out_of_range("bucket_map::get_bucket");
        }
        
        return bucket_arrays_[ba_index].first.bucket(b_pos);
    }
    
    inline bucket_type get_bucket(const std::pair<uint8_t, size_t> &p)
    {
        return get_bucket(p.first, p.second);
    }
    
    inline const bucket_type get_bucket(const std::pair<uint8_t, size_t> &p) const
    {
        return get_bucket(p.first, p.second);
    }

    
    mapped_type& at_overflow_bucket(size_t hkey)
    {
        size_t index = get_overflow_bucket_index(hkey);
        auto& submap = overflow_map_.at(index);
        return submap.at(hkey).second;
    }

    const mapped_type& at_overflow_bucket(size_t hkey) const
    {
        size_t index = get_overflow_bucket_index(hkey);
        auto& submap = overflow_map_.at(index);
        return submap.at(hkey).second;
    }

    bool get_overflow_bucket(size_t hkey, mapped_type& v) const
    {
        size_t index = get_overflow_bucket_index(hkey);
        
        auto const it = overflow_map_.find(index);
        
        if (it != overflow_map_.end()) {
            auto const map_it = it->second.find(hkey);
            
            if (map_it != it->second.end()) {
                v = map_it->second.second;
                return true;
            }
        }
        
        return false;
    }
    
    void append_overflow_bucket(size_t bucket_index, size_t hkey, const value_type& v)
    {
        auto const it = overflow_map_.find(bucket_index);
        
        if (it != overflow_map_.end()) {
            it->second.insert(std::make_pair(hkey, v));
        }else{
            overflow_submap_type m;

            m.insert(std::make_pair(hkey, v));
            
            overflow_map_.insert(std::make_pair( bucket_index , m)); // move ????

        }
        
        overflow_count_++;
    }

    void append_overflow_bucket(size_t hkey, const value_type& v)
    {        
        size_t index = get_overflow_bucket_index(hkey);
        append_overflow_bucket(index, hkey, v);
    }
    
    inline bool should_resize() const
    {
        // return yes if the map should be resized to reduce the load and/or the size of the overflow bucket
        if(e_count_ > kBucketMapResizeThresholdLoad*bucket_space_ )
        {
            if (overflow_count_ >= kBucketMapResizeMaxOverflowSize) {
                return true;
            }else if (overflow_count_ >= kBucketMapResizeMaxOverflowRatio * e_count_){
                return true;
            }
        }
        
        if(overflow_count_ >= 10*kBucketMapResizeMaxOverflowSize)
        {
            return true;
        }
        
        
        return false;
    }
    
    void finalize_resize()
    {
        mask_size_++;
        resize_counter_ = 0;
        is_resizing_ = false;
        
//        std::cout << "Done resizing!" << std::endl;

    }
    
    void online_resize()
    {
        for (size_t i = 0; i < kBucketMapResizeStepIterations && is_resizing_; i++) {
            resize_step();
        }
    }
    
    void resize_step()
    {
        // read a bucket and rewrite some of its content somewhere else
        
        // get the bucket pointed by resize_counter_
        std::pair<uint8_t, size_t> coords = bucket_coordinates(resize_counter_);
        auto b = get_bucket(coords);

        size_t mask = (1 << mask_size_);
        auto new_bucket = bucket_arrays_.back().first.bucket(resize_counter_);
        new_bucket.set_size(0);
        
        size_t c_old = 0;
        auto it_old = b.begin();
        
        for (auto it = b.begin(); it != b.end(); ++it) {
            if ((hf_(it->first) & mask) == 0) { // high order bit of the key is 0
                // keep it here
                memcpy(it_old, it, sizeof(value_type));
                ++it_old;
                c_old++;
            }else{
                // append it to the other bucket
                bool success = new_bucket.append(*it);
                
                if (!success) {
                    // append the pair to the overflow bucket
                    size_t h = hf_(it->first);

                    append_overflow_bucket(h&((1 << (mask_size_+1))-1), h, *it);
                }
            }
        }
        // set the new size of the old bucket
        b.set_size(c_old);
        
        
        // now, try to put as many elements from the overflow bucket as possible
        auto const bucket_it = overflow_map_.find(resize_counter_);
        
        bool success;
        
        if (bucket_it != overflow_map_.end()) {
            // initialize the current bucket
            overflow_submap_type current_of_bucket(std::move(bucket_it->second));
            
            // erase the old value
            overflow_map_.erase(resize_counter_);
            
            overflow_count_ -= current_of_bucket.size();
            
            // enumerate the bucket's content and try to append the values to the buckets
            for (auto &elt: current_of_bucket) {

                if (((elt.first) & mask) == 0) { // high order bit of the key is 0
                    success = b.append(elt.second);
                    if (!success) { // add the overflow bucket
                        append_overflow_bucket(resize_counter_, elt.first, elt.second);
                    }
               }else{
                    success = new_bucket.append(elt.second);
                   if (!success) { // add the overflow bucket
                       append_overflow_bucket(mask ^ resize_counter_, elt.first, elt.second);
                   }
                }
                
            }

        }

        
        // check if we are done
        if (resize_counter_ == (mask -1)) {
            finalize_resize();
        }else{
            resize_counter_ ++;
        }
        
        bucket_space_ += bucket_arrays_.back().first.bucket_size();
    }
    
    void init_from_file()
    {
        // start by reading the meta data
        struct stat buffer;
        
        std::string meta_path = base_filename_ + "/meta.bin";

        if (stat (meta_path.data(), &buffer) != 0) { // the meta data file is not there
            throw std::runtime_error("bucket_map constructor: metadata file does not exist");
        }

        mmap_st meta_mmap = create_mmap(meta_path.data(), sizeof(metadata_type));
        
        metadata_type *meta_ptr = (metadata_type *)meta_mmap.mmap_addr;
        
        original_mask_size_     = meta_ptr->original_mask_size;
        is_resizing_            = meta_ptr->is_resizing;
        resize_counter_         = meta_ptr->resize_counter;
        e_count_                = meta_ptr->e_count;
        
        mask_size_ = original_mask_size_ + meta_ptr->bucket_arrays_count -1;
        
        size_t N = 1 << (original_mask_size_);
        
        bucket_space_ = 0;

        for (uint8_t i = 0; i < meta_ptr->bucket_arrays_count; i++) {
            size_t length = N  * kPageSize;
            
            std::string fn = base_filename_ + "/data." + std::to_string(i);
            
            if (stat (fn.data(), &buffer) != 0) { // the file is not there
                throw std::runtime_error("bucket_map constructor: " + std::to_string(i) + "-th data file does not exist.");
            }

            mmap_st mmap = create_mmap(fn.data(),length);
            
            bucket_arrays_.push_back(std::make_pair(bucket_array_type(mmap.mmap_addr, N, kPageSize), mmap));
            
            if (is_resizing_ == false || i < meta_ptr->bucket_arrays_count-1) {
                bucket_space_ += bucket_arrays_[i].first.bucket_size() * bucket_arrays_[i].first.bucket_count();
            }else{
                bucket_space_ += resize_counter_*bucket_arrays_[i].first.bucket_size() * bucket_arrays_[i].first.bucket_count();
            }

            if (i > 0) {
                N <<= 1;
            }
        }

        // read the overflow bucket
        
        if (meta_ptr->overflow_count > 0) {
            std::string overflow_path = base_filename_ + "/overflow.bin";

            if (stat (overflow_path.data(), &buffer) != 0) { // the overflow file is not there
                throw std::runtime_error("bucket_map constructor: Overflow file does not exist.");
            }
            
            mmap_st over_mmap = create_mmap(overflow_path.data(), (meta_ptr->overflow_count)*sizeof(typename overflow_map_type::value_type));
            
            typedef std::pair<size_t, std::pair<size_t,value_type>> pair_type;
            pair_type* elt_ptr = (pair_type*) over_mmap.mmap_addr;
            
            for (size_t i = 0; i < meta_ptr->overflow_count; i++) {
                append_overflow_bucket(elt_ptr[i].first, elt_ptr[i].second.first, elt_ptr[i].second.second);
            }
            
            // close the overflow mmap
            close_mmap(over_mmap);
        }

        // close the metadata map
        close_mmap(meta_mmap);
    }
    
    const bucket_array_type& get_bucket_array(size_t i) const
    {
        return bucket_arrays_[i].first;
    }
    
};

} // namespace ssdmap