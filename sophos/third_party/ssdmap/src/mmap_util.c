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


#include "mmap_util.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <errno.h>

mmap_st create_mmap(const char *pathname, size_t length)
{
    off_t result;
    mmap_st map;
    
    map.length = 0;
    map.mmap_addr = NULL;
    
    if (length == 0) {
        perror("Invalid length");
        exit(EXIT_FAILURE);
    }
    map.fd = open(pathname, O_RDWR | O_CREAT, (mode_t)0600); // permissions set to rw-----
    if (map.fd == -1) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    result = lseek(map.fd, length-1, SEEK_SET);
    if (result == -1) {
        close(map.fd);
        perror("Error calling lseek() to 'stretch' the file");
        exit(EXIT_FAILURE);
    }
    

    // stretch the file if needed
    char buf[1]="";
    
    result = read(map.fd, buf,1);
    if (result != 1) {
        // the file was not streched
//        printf("Stretch!\n");

        result = write(map.fd, buf, 1);
        if (result != 1) {
            close(map.fd);
            perror("Error writing last byte of the file");
            exit(EXIT_FAILURE);
        }
    }

    
    // mmap the file
    map.mmap_addr = mmap(0, length, PROT_READ | PROT_WRITE, MAP_SHARED, map.fd, 0);
    if (map.mmap_addr == MAP_FAILED) {
        close(map.fd);
        perror("Error mmapping the file");
        exit(EXIT_FAILURE);
    }
    
    // we will use random access in our use case
    if(madvise(map.mmap_addr, length, MADV_RANDOM) == -1)
    {
        printf("Bad advice ...\n");
    }
    
    map.length = length;

    return map;
}

int flush_mmap(mmap_st map, flush_flag sync_flag)
{
    int ret;
    
    ret = msync(map.mmap_addr, map.length, ((sync_flag == ASYNC_FLAG) ? MS_ASYNC : MS_SYNC));
    
    if (ret == -1) {
        perror("Error syncing the map.");
    }
    
    return ret;
}

int close_mmap(mmap_st map)
{
    int ret = 0;
    size_t offset = 0;
    size_t step = 1 << 30; // 1 GB step
    
    for (; offset < map.length; offset += step) {
        if (map.length - offset >= step) {
            if (munmap(map.mmap_addr+offset, step) == -1) {
                perror("Error un-mmapping the file");
                ret = -1;
                /* Decide here whether to close(fd) and exit() or not. Depends... */
            }
        }else{
            if (munmap(map.mmap_addr+offset, map.length - offset) == -1) {
                perror("Error un-mmapping the file");
                ret = -1;
                /* Decide here whether to close(fd) and exit() or not. Depends... */
            }
        }
    }
//    if (munmap(map.mmap_addr, map.length) == -1) {
//        perror("Error un-mmapping the file");
//        ret = -1;
//        /* Decide here whether to close(fd) and exit() or not. Depends... */
//    }
//
    // close the file descriptor
    ret += close(map.fd);
    
    return ret;
}