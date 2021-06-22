/* * ssdmap - Implementation of a disk-resident map designed for SSDs.
 * Copyright (C) 2016 Raphael Bost
 *
 * This file is part of ssdmap.
 *
 * ssdmap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ssdmap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ssdmap.  If not, see <http://www.gnu.org/licenses/>.
 */



/** @file mmap_util.h
 * @brief Header defining handy functions to manage memory maps.
 *
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
    
/**
 *  @brief  Representation of a memory map.
 *
 *
 *  This structure stores all the necessary informations to easily manage a memory map.
 *
 */
typedef struct
{
    void *mmap_addr;    /**< @brief The mapped memory adress    */
    size_t length;      /**< @brief The number of mapped bytes  */
    int fd;             /**< @brief The file descriptor of the mapped file */
}mmap_st;

/**
 *  @brief Initialize a new memory map
 *
 *  Create a new memory map of @a length bytes mapped to the file at path @a pathname.
 *  If there is no file at @a pathname, a new file with mode 0600 will be create.
 *  Also, the function will ensure that @a length bytes are accessible by reading and writing the last length-1-th byte of the file.
 *  
 *
 *  @param pathname The path of the mapped file.
 *  @param length   Size (in bytes) of the mapped memory. @a length must be stricly larger than 0, or the function will fail.
 *
 *  @return A mmap_st structure representing the memory map. If the function failed, the mmap_addr field of the return value will be set to NULL, and its length to 0.
 */
mmap_st create_mmap(const char *pathname, size_t length);

/**
 *  @brief Arguments flags for the flush_mmap function
 *
 */
typedef enum{
    ASYNC_FLAG = 0, /**< @brief Specifies that an update be scheduled, but the call returns immediately. */
    SYNC_FLAG = 1   /**< @brief Requests an update and waits for it to complete. */
} flush_flag;
    
/**
 *  @brief Flush changes made to the in-core copy of the memory map to the mapped file.
 *
 *  @param  map         The mmap_st structure representing a memory map.
 *  @param  sync_flag   One of the flags specified by the flush_flag enum.
 *
 *  @return zero on success, -1 on error, and errno is set appropriately according to msync(2).
 */
int flush_mmap(mmap_st map, flush_flag sync_flag);
    
    
/**
 *  @brief Close a memory map.
 *
 *  Unmaps the memory map and closes the associated file descriptor. When unmapped, the memory is flushed to the file.
 *
 *  @param  map         The mmap_st structure representing a memory map.
 *
 *  @return zero on success, -1 if unmapping or (exclusively) closing the file descriptor failed, -2 if both failed.
 */
int close_mmap(mmap_st);
    
    
#ifdef __cplusplus
}
#endif