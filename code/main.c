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



int stub_get_devid(int8_t *devid)
{
    int8_t testid[DEV_ID_LEN_MAX] = "yuge_server001";

    if (devid != NULL)
        strcpy(devid, testid);

    return OK;
}



int init_proc_data(proc_spec_data_t *priv)
{
    int32_t ret;
    int8_t  svr_devid[DEV_ID_LEN_MAX] = {0};
    
    INIT_LIST_HEAD(&priv->dev_list_head);
    ret = pthread_mutex_init(&priv->dev_mutex, NULL);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, INIT, "pthread_mutex_init ret:%d", ret);
    }

    //stub
    stub_get_devid(priv->devid);

    return OK;
}

/* port can be customized */
int main(int argc, char *argv[])
{
    int32_t ret;
    char val[16] = {0};
    uint32_t port= 0;
    int8_t   tmp_pkey[PUB_KEY_LEN_MAX] = {0}; /* temporary key for comm with sk-centor */

    /* parse param */
    if (argc < 2)
    {
        printf("listen port not input, use %d as default.\n", SVR_LISTEN_PORT_NUM);
        port = SVR_LISTEN_PORT_NUM;
    }
    else
    {
        if ((strlen(argv[1]) <1) || (argv[1][0] == '0'))
        {
            printf("port %s illegal.\n", argv[1]);
            return -1;
        }
        printf("listen port %s\n", argv[1]);
        strcpy(val, argv[1]);
        
        port = strtoul(val, 0, 0);
    }

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
    proc_data ->sockfd = init_monitor(NULL, port);
    
    log_info(MSG_LOG_DBG, INIT, "start monitor, svr_fd:%ld", proc_data ->sockfd);

    if (proc_data ->sockfd > 0)
        start_monitor(proc_data ->sockfd);


    /* 5 to be continued... */


    // run here, when all task exit
    close_monitor(proc_data);
    log_info(MSG_LOG_DBG, INIT, "shutdown monitor OK");

    return 0;
}


/* print key words that affect flow running */
void dbg_print_key_words(proc_spec_data_t *priv)
{
    if (!priv)
        return;

    log_info(MSG_LOG_DBG, DBG, "key words as follow:");
    log_info(MSG_LOG_DBG, DBG, "server devid:%s", priv->devid);
    log_info(MSG_LOG_DBG, DBG, "socket fd:%d", priv->sockfd);
    log_info(MSG_LOG_DBG, DBG, "client_num:%d", priv->client_num);
    log_info(MSG_LOG_DBG, DBG, "\n");

}


