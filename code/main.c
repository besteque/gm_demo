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



int init_proc_data(proc_spec_data_t *priv)
{
    int32_t ret;
    INIT_LIST_HEAD(&priv->dev_list_head);
    ret = pthread_mutex_init(&priv->dev_mutex, NULL);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, INIT, "pthread_mutex_init ret:%d", ret);
    }

    //stub
    strcpy(priv->devid, "xuyang_1000e");

    return OK;
}


int main(int argc, char *argv[])
{
    int32_t ret;
    int8_t   tmp_pkey[PUB_KEY_LEN_MAX] = {0}; /* temporary key for comm with sk-centor */


    /* 0 init proc private data */
    proc_data = (proc_spec_data_t*)malloc(sizeof(proc_spec_data_t));
    if (proc_data == NULL)
    {
        log_info(MSG_LOG_DBG, INIT, "main alloc mem failed");
        return ERROR;
    }
    memset(proc_data, 0, sizeof(proc_spec_data_t));

    /* 1 init TE dev list  */
    init_proc_data(proc_data);

    /* 2 get secret key from sk-center, gen pk and sk  */
    log_info(MSG_LOG_DBG, INIT, "init sw shield begin...");
    ret = init_sw_shield(proc_data->devid, tmp_pkey);
    if (ret != OK)
        return -1;
    log_info(MSG_LOG_DBG, INIT, "init sw shield OK");

    /* 3 generate key matrix */
    log_info(MSG_LOG_DBG, INIT, "gene_key_matrix begin");
    gene_key_matrix(proc_data->pub_matrix, proc_data->skey_matrix);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, INIT, "gene_key_matrix failed, code:%ld", ret);
        return ERROR;
    }    
    log_info(MSG_LOG_DBG, INIT, "gene_key_matrix OK");

    // stub: verify API
    dbg_test_verify(proc_data->devid, proc_data->pub_matrix, PUB_KEY_MATRIX_LEN_MAX);

    
    /* 4 start service monitor */
    proc_data ->sockfd = init_monitor(NULL, SVR_LISTEN_PORT_NUM);
    
    log_info(MSG_LOG_DBG, INIT, "start monitor, svr_fd:%ld", proc_data ->sockfd);

    if (proc_data ->sockfd > 0)
        start_monitor(proc_data ->sockfd);


    /* 5 to be continued... */


    // run here, when all task exit
    close_monitor(proc_data);
    log_info(MSG_LOG_DBG, INIT, "shutdown monitor OK");

    return 0;
}


