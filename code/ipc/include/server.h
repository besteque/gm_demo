/*
 * server.h
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */

#ifndef _SERVER_H_
#define _SERVER_H

#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <stdint.h>

#include "pub.h"
#include "common.h"


//#define BUFSIZ      1024

uint32_t init_monitor(int8_t *addr, uint32_t port) ;
uint32_t start_monitor(uint32_t svr_fd);
uint32_t close_monitor(uint32_t svr_fd);


#endif

