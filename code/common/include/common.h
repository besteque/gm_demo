/*
 * common.h
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#include "list.h"
#include "pub.h"



//#define PUB_KEY_LEN_MAX         256
//#define SECRET_KEY_LEN_MAX      1024

#define FILE_PATH_NAME_LEN_MAX      256
#define DATE_TIME_STR_LEN_MAX       32
#define PRINT_MSG_LEN_MAX           1024    // need discuss!
#define INVALID_SOCKET_FD           -1

#define INVALID_UINT32           -1


#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef enum tag_msg_log_level
{
    MSG_LOG_DBG = 0,
    MSG_LOG_FILE,

    MSG_LOG_MAX,
}msg_log_level_t;

typedef enum tag_module_def
{
    INIT = 0,
    IPC,
    MGT,
    SVR,
    CRYPT,
}module_def_t;
    
typedef enum tag_error_num
{
    OK = 0,
    FINISH,
    ERROR,
}error_num_t;


typedef struct tag_device_info
{
    list_t      member;
    uint8_t     id[DEV_ID_LEN_MAX];                /* device id      */
    uint32_t    dev_type;                           /* device type      */
    uint32_t    algorithm;                          /* data    encrypt algorithm, ref:encrpyt_alg_type_t         */
    int8_t      com_key[SECRET_KEY_LEN_MAX];            /* communication       secret   key */
    signiture_data_t sign_data;                     /* device signiture data */
    encrypt_data_t          crypt_type;              /* symmetric encryption algorithm */
    int8_t      pad[1024];
    
}dev_info_t;

/*typedef struct tag_svr_priv_data
{
    task_id;
    public_key;
    pk_matrix    

}svr_priv_data_t;*/

typedef struct tag_svr_task_data
{
    uint8_t     id[DEV_ID_LEN_MAX];
    char        data[SIGN_DATA_LEN_MAX];

}task_priv_data_t;

//may be '__VA_ARGS__' or '##__VA_ARGS__' or '##args'
#define PRINT_SYS_MSG(level, module, fmt, ...)    \
    do{                                            \
        if (level == MSG_LOG_DBG) {                \
            print_sys_msg(#module, (fmt), ##__VA_ARGS__);\
        }                                           \
        else {                                      \
            rel_slogf(fmt, ##__VA_ARGS__);                 \
        }                                           \
    }while(0)


extern uint8_t     session_id[];
void get_dev_id(uint8_t *id);
void record_dev_id(uint8_t *id);



void     getcurtime(uint8_t *dtime, uint32_t len);
uint32_t rel_slogf(const uint8_t *fmt, ...);
uint32_t print_sys_msg(const uint8_t *module, const uint8_t *fmt, ...);

uint32_t getpid_by_name(const uint8_t* procname);

void dbg_print_cur_dir(void);
void dbg_print_msg_head(msg_head_t *head);


#endif

