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

void dbg_test_verify(char * devid, uint8_t *matrix, uint32_t klen);

uint32_t encrypt_data(encrypt_data_t *algorithm, int8_t *orig_data,uint32_t orig_len, 
                            int8_t *ciph_data,uint32_t *ciph_len);
uint32_t decrypt_data(encrypt_data_t *algorithm, int8_t *ciph_data,uint32_t ciph_len, 
                            int8_t *orig_data,uint32_t *orig_len);


#endif

