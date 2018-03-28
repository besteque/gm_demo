/*
 * pub.h
 *
 *  Created on: 2018-3-20
 *      Author: xuyang
 */


#ifndef _PUB_H_
#define _PUB_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/* communication port */
#define SVR_LISTEN_PORT_NUM                 5069        /* server monitor port */
#define CLI_LISTEN_PORT_NUM                 5068        /* client monitor port */

#define MAGIC_WORD                          "@YGET@"  /* YuGe Electronic Technology ltd. */

#define SERVER_VERIFY_DATA_SYMBOL           "YGET SECURITY SERVER"
#define CLIENT_VERIFY_DATA_SYMBOL           "YGET SECURITY CLIENT"

#define MAGIC_WORD_LEN_MAX                  8

#define PACKAGE_DATA_LEN_MAX                1024  //to big... must small then 1024 todo....... divide pkg ourself!!!
#define DEV_ID_LEN_MAX                      128
#define SIGN_DATA_LEN_MAX                   512
#define PUB_KEY_LEN_MAX                     512         /* public secret key length max value */
#define SYMMETRIC_KEY_LEN                   16          /* use to generate symmetric key, and constraint encrypt-decrypt data len */

#define SECRET_KEY_LEN_MAX                  1024        /* private secret key length max value */
#define SECRET_KEY_LEN_MIN                  32          /* private secret key length min value */

#define PUB_KEY_MATRIX_LEN_MAX              66816       /* public key matrix len:1024*65(66560), add 256 as reserve */
#define SECRET_KEY_MATRIX_LEN_MAX           33024       /* secret key matrix len:1024*32, add 256 as reserve */

#define CIPHER_DATA_LEN_MAX             1024  /* equivalent to:pkg len subtract msg head size */

typedef enum tag_msg_type 
{
    MSG_TYPE_INIT = 0,
    MSG_TYPE_LOGIN,
    MSG_TYPE_SIGNITURE,
    MSG_TYPE_ENCRYPT_INFO,     /* transmit encrpyt type and key, encapsulate in data segment*/
    MSG_TYPE_USR_DATA,

    MAX_MSG_TYPE = MSG_TYPE_USR_DATA,
} msg_type_t;

typedef enum tag_encryp_alg_type 
{
    ALG_TYPE_NULL = 0,
    ALG_TYPE_RSA,
    ALG_TYPE_DES,
    ALG_TYPE_DES3,
    ALG_TYPE_AES,
    ALG_TYPE_SM2,
    ALG_TYPE_SM3,
    ALG_TYPE_SM4,   // ----ecb for default,encrypt_data_t 需要增加模式，如CBC/EBC...
    ALG_TYPE_BASE64,

    INVALID_ENCYPT_ALG_TYPE = -1,
} encrpyt_alg_type_t;


typedef struct tag_msg_head 
{
    unsigned char     magic[MAGIC_WORD_LEN_MAX];                 /* ref:MAGIC_WORD */
    unsigned short     type;                    /* message type, ref: msg_type_t*/
    unsigned short     data_len;                /* current package data length (original) */
    unsigned short     version;                  /* message version */
    unsigned short     trans_id;                /* transaction id, same id for each connection                    */
    unsigned int     total_length;              /* data total length */
    unsigned short     total_package;           /* total_package                         \
                                                    =(total_length + PACKAGE_DATA_LEN_MAX-1)/PACKAGE_DATA_LEN_MAX */
    unsigned short     index;                   /* package index *//* package length is PACKAGE_DATA_LEN_MAX bytes */

    unsigned int err_type;      /* error number, 0-OK */
    unsigned char     pad2[28];
} msg_head_t;

/* ref:MSG_TYPE_LOGIN  */
typedef struct tag_login_data
{
    unsigned char dev_id[DEV_ID_LEN_MAX];
    char pad[128];
}login_data_t;


/* ref:MSG_TYPE_SIGNITURE */
typedef struct tag_signiture_data
{
    char data[SIGN_DATA_LEN_MAX];
    char pad[512];
}signiture_data_t;


/* ref:MSG_TYPE_ENCRYPT_INFO */
typedef struct tag_encrypt_data
{
    unsigned int    algorithm;           /*  enumeration data, ref:encrpyt_alg_type_t,default 0-RSA*/
    char key[SECRET_KEY_LEN_MAX];
    int   mode;       /* SM4_MODE_ECB/SM4_MODE_CBC */
    int padding;        /* SM4_PKCSPADDING / SM4_NOPADDING */
    unsigned char vector[20];   /* offset,   CBC need fill it */
    char pad[228];  ////////////////////大于1460，tcp分包了  todo.....
}encrypt_data_t;


typedef struct tag_msg_ctx {
    msg_head_t head;
    char            data[0];
} msg_context_t;


#endif

