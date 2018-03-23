/*
 * common.h
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include "apkapi.h"
#include "apply_2_server.h"


uint32_t init_sw_shield(int8_t *dev_id, int8_t *key);
uint32_t persist_secret_key(int8_t *dev_id, int8_t *pkey);

void init_sw_shield_ex(int8_t *dev_id, int8_t *pkey);



