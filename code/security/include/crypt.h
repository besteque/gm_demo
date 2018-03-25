/*
 * common.h
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */
 #ifndef _CRYPT_H_
#define _CRYPT_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include "apkapi.h"
#include "apply_2_server.h"
#include "common.h"


uint32_t init_sw_shield(int8_t *dev_id, int8_t *key);
uint32_t persist_secret_key(int8_t *dev_id, int8_t *pkey);
uint32_t init_sw_shield_ex(int8_t *dev_id, int8_t *pkey);
uint32_t gene_key_matrix(BYTE *pub_matrix, BYTE * skey_matrix);


#endif

