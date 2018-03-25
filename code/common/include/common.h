/*
 * common.h
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "list.h"
#include "pub.h"



#define DEBUG_TRUE          1
#define DEBUG_FALSE         0
#define F_DESC(x)        0      // use for code interpret


#define FILE_PATH_NAME_LEN_MAX      256
#define DATE_TIME_STR_LEN_MAX       32
#define PRINT_MSG_LEN_MAX           1024    // need discuss!
#define INVALID_SOCKET_FD           -1
#define TCP_CONNECT_POOL            5

#define INVALID_UINT32           -1

#define PROC_THREAD_NUM_MAX         TCP_CONNECT_POOL /* max thread in proccess, imply socket connect number */

#define IWALL_SVKD_REPO             "res/svkd/"
#define SMT_PKM_FILE                "res/iwall/iwall.smt.pkm"
#define SMT_SKM_FILE                "res/iwall/iwall.smt.skm"


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
    ERROR,
    FINISH,
    KEY_EXIST_IN_SERVER,
}error_num_t;


typedef struct tag_device_info
{
    struct list_head       point;
    int8_t      id[DEV_ID_LEN_MAX];                /* device id      */
    uint32_t    dev_type;                           /* device type      */
    uint32_t    algorithm;                          /* data    encrypt algorithm, ref:encrpyt_alg_type_t         */
    signiture_data_t sign_data;                     /* device signiture data */
    encrypt_data_t          crypt_type;              /* symmetric encryption algorithm */
    int8_t      pad[1024];
    
}dev_info_t;

typedef struct tag_svr_priv_data
{
    struct list_head dev_list_head;
    int8_t devid[DEV_ID_LEN_MAX];               /* svr device id */
    int32_t cli_sockfd[PROC_THREAD_NUM_MAX];         /* client socket fd */
    int32_t task_id[PROC_THREAD_NUM_MAX];         /* max threads number in the proc */
    uint8_t pub_matrix[PUB_KEY_MATRIX_LEN_MAX];     /* server is owner */
    uint8_t skey_matrix[SECRET_KEY_MATRIX_LEN_MAX]; /* server is owner */

}proc_spec_data_t;

/* for every connect, create a task, it can register multi-device */
typedef struct tag_svr_task_data
{
    int8_t      devid[DEV_ID_LEN_MAX];     /* TE device id */ /* use as unique index*/
    int32_t     cli_sockfd;
    uint32_t    total_rcv_data_len; /* rc data total len(without head) in every step, reset for each step over */

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


// external variable
extern int8_t     session_id[];
extern proc_spec_data_t *proc_data;


typedef void* (*THREAD_ENTRY)(void *);



uint32_t get_proc_priv_data(proc_spec_data_t **priv);


void get_dev_id(int8_t *id);
void record_dev_id(int8_t *id);



void     getcurtime(uint8_t *dtime, uint32_t len);
uint32_t rel_slogf(const uint8_t *fmt, ...);
uint32_t print_sys_msg(const uint8_t *module, const uint8_t *fmt, ...);

uint32_t getpid_by_name(const uint8_t* procname);

void dbg_print_cur_dir(void);
void dbg_print_msg_head(msg_head_t *head);
void dbg_print_devinfo(dev_info_t    *devinfo);
void dbg_print_dev_list(struct list_head *head);
void dbg_print_char_in_buf(int8_t *buf, uint32_t len);
void dbg_add_data_to_list(struct list_head *head);




#endif

