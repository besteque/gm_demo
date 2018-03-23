/*
 * main.c
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */


#include "pub.h"
#include "common.h"
#include "mgt.h"
#include "server.h"


/* WARNing:need semaphore to protect it in multi-thread env  */
list_t      dev_list_head = {0};


extern main_crypt();



int main() 
{
    uint32_t sock_fd;
    int8_t   tmp_pkey[PUB_KEY_LEN_MAX] = {0}; /* temporary key for comm with sk-centor */

    //stub
    int8_t svr_id[20] = "xuyang1024";
    char ursid[512] = {0};
    int     id_len;

    /* 1 init TE dev list  */
    int_device_list(&dev_list_head);

#if 0 //DENY
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "init sw shield");
    init_sw_shield(svr_id, tmp_pkey);    
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "%s's pk:%s", svr_id, tmp_pkey);

    /* 2 get secret key from sk-center  */
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "get secret key from sk-center");
    persist_secret_key(svr_id);
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "get secret key from sk-center OK");
#else

    /* 2 generate pk and apply sk */
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "get secret key from sk-center");
    init_sw_shield_ex(svr_id, tmp_pkey);
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "get secret key from sk-center OK");
#endif
    
    /*IW_OpenDevice(svr_id, "svkd/");
    IW_ReadKeyID(ursid, &id_len);
    ursid[id_len] = '\0';
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "urdid:%s, len:%ld", ursid, id_len);*/

    
    /* 3 start service monitor */
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "start monitor...");    
    sock_fd = init_monitor(NULL, SVR_LISTEN_PORT_NUM);
    start_monitor(sock_fd);

    close_monitor(sock_fd);
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "shutdown monitor...");  

    /* 4 to be continued... */

    return 0;
}


