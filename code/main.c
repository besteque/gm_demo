/*
 * main.c
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */


#include "pub.h"
#include "common.h"
#include "crypt.h"
#include "mgt.h"
#include "server.h"



/* WARNing:need semaphore to protect it in multi-thread env  */
proc_spec_data_t *proc_data = NULL;
//struct list_head      dev_list_head = {0};


extern main_crypt(void);


int init_proc_data(proc_spec_data_t *priv)
{    
    INIT_LIST_HEAD(&priv->dev_list_head);

    //stub
    strcpy(priv->devid, "xuyang_00n");

    return OK;
}


int main(int argc, char *argv[])
{
    int32_t ret;
    uint32_t sock_fd;
    int8_t   tmp_pkey[PUB_KEY_LEN_MAX] = {0}; /* temporary key for comm with sk-centor */


    /* 0 init proc private data */
    proc_data = malloc(sizeof(proc_spec_data_t));
    if (proc_data == NULL)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "main alloc mem failed");
        return ERROR;
    }
    memset(proc_data, 0, sizeof(proc_spec_data_t));

    /* 1 init TE dev list  */
    init_proc_data(proc_data);

    /* 2 get secret key from sk-center, gen pk and sk  */
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "init sw shield begin...");
    ret = init_sw_shield(proc_data->devid, tmp_pkey);
    if (ret != OK)
        return -1;
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "init sw shield OK");

    /* 3 generate key matrix */
    //gene_key_matrix(proc_data->pub_matrix, proc_data->skey_matrix);
    
    /* 4 start service monitor */
    sock_fd = init_monitor(NULL, SVR_LISTEN_PORT_NUM);
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "start monitor, svr_fd:%ld", sock_fd);

    if (sock_fd > 0)
        start_monitor(sock_fd);

    close_monitor(sock_fd);
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "shutdown monitor, svr_fd:%ld", sock_fd);

    /* 5 to be continued... */

    return 0;
}


