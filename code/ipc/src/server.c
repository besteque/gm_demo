/*
 * server.c
 *
 *  Created on: 2018-3-21
 *      Author: xuyang
 */


#include "server.h"
#include "mgt.h"


/***************************************************************
*            global data
****************************************************************/
//uint32_t    total_rcv_data_len = 0;
//int8_t      session_id[DEV_ID_LEN_MAX] = {0};   // in multi-thread scene, each thread has a session_id

task_priv_data_t task_data = {0};



/***************************************************************
*           functions
****************************************************************/
void init_session_data(task_priv_data_t *priv)
{
    //total_rcv_data_len = 0;
    //session_id[0] = '\0';

    memset(priv->devid, 0, DEV_ID_LEN_MAX);
    priv->total_rcv_data_len = 0;
}


uint32_t calc_total_len(task_priv_data_t *priv, uint32_t len)
{
    priv->total_rcv_data_len += len;
    return OK;
}

uint32_t get_total_len(void)
{

    return task_data.total_rcv_data_len;
}


/*
*   1 endian convert  --TODO!!!!!!!!
*   2  free buf when data been sent 
*/
uint32_t send_to_client(uint32_t fd, int8_t *data, uint32_t len)
{
    if (send(fd,data,len,0) < 0)  
    {  
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "response_to_client failed.");  
        return ERROR;  
    } 

    return OK;
}


/*
*   use "netstat -ntlp" to see port info
*   return: socketfd
*/
uint32_t init_monitor(int8_t *addr, uint32_t port) 
{
    int32_t svr_fd = -1;
    struct sockaddr_in svr_addr;   
    uint32_t sin_size;  
    int8_t   buf[BUFSIZ] = {0};  

    memset(&svr_addr,0,sizeof(svr_addr));
    svr_addr.sin_family = AF_INET; 
    svr_addr.sin_addr.s_addr = (!addr?INADDR_ANY:inet_addr(addr));
    svr_addr.sin_port = htons(port);

    if ((svr_fd = socket(AF_INET,SOCK_STREAM,0))<0)  
    {    
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "create socket failed.");  
        return ERROR;  
    }  

    if (bind(svr_fd,(struct sockaddr *)(&svr_addr),sizeof(struct sockaddr))==-1)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "bind error, fd:%d", svr_fd);
        return ERROR;  
    }

    return svr_fd;
}


uint32_t start_monitor(uint32_t svr_fd)
{
    int32_t ret;  
    int32_t len = 0;  
    uint32_t sin_size = sizeof(struct sockaddr_in);  
    int32_t  client_fd; 
    int8_t   buf[BUFSIZ]; 
    int8_t   *ack_data;
    uint32_t ack_len;
    struct sockaddr_in client_addr;
    pthread_t th_id;
    proc_spec_data_t *proc_priv;
    //task_priv_data_t task_data = {0};   //stub

    if (listen(svr_fd, TCP_CONNECT_POOL) == -1)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "listen error");
        return ERROR;  
    }


    while(1)
    {
        // same client has unique fd, if not closed or timeout
        if((client_fd = accept(svr_fd, (struct sockaddr *)(&client_addr), &sin_size)) == -1)
        {
            PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "accept error");
            continue;
        }
        
        /* 
            for each     transaction, init        counter before       preserve data
            create task, init priv data:task_priv_data_t
            thread id asigned by proc, restrict by PROC_THREAD_NUM_MAX
        */
        get_proc_priv_data(&proc_priv);
        if ((client_fd != proc_priv->cli_sockfd[0]))
        {
            init_session_data(&task_data);
            task_data.cli_sockfd = client_fd;
            pthread_create(&th_id, NULL, secure_comm_task, (void*)&task_data);

            // stub task_id serial id0 todo...
            proc_priv->task_id[0] = th_id;
            proc_priv->cli_sockfd[0] = client_fd;
        }        
        
        
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "client %s been connected.", inet_ntoa(client_addr.sin_addr));

        //getsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &stat, (socklen_t *)&len); 


        // set timer, when task_data.total_rcv_data_len when timeout
        
        while ((len = recv(client_fd, buf, BUFSIZ, 0)) > 0)
        {
            
            PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "recv data len:%ld", len);
        
            if (validate_data(buf, len) != OK)
                continue;

            
             /* transaction */
            if ((ret = parse_data(buf, len)) == FINISH)
            {
                prepare_interactive_data(((msg_head_t*)buf)->type, &ack_data, &ack_len);
                
                send_to_client(client_fd, ack_data, ack_len);
                
                PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "send_to_client OK");
                //PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "data sent to client:%s", ack_data+sizeof(msg_head_t));
                dbg_print_char_in_buf(ack_data+sizeof(msg_head_t), 64);


                /* release resources */
                //total_rcv_data_len = 0;
                task_data.total_rcv_data_len = 0;
                free(ack_data);
                continue;
            }

            if (ret == OK   )
                PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "receive next package data");
        }
    
        close(client_fd);

        // need timer, or may cause deadloop
        
    } 

    return OK;
}


uint32_t close_monitor(uint32_t svr_fd)
{
    if(svr_fd != INVALID_SOCKET_FD)        
        close(svr_fd);

    //free devlist
    //free task var

    return OK;
}


uint32_t client_connect_timeout()
{
    //close fd
    //free task var

    return OK;
}

void* secure_comm_task(void *priv)
{
    proc_spec_data_t *proc;
    task_priv_data_t *task_data = (task_priv_data_t *)priv;

    get_proc_priv_data(&proc);
    
    PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "task id is:%d", proc->task_id[0]);



    while(1)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "priv->cli_sockfd:%d", proc->cli_sockfd[0]);
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "task_data->devid:%s", task_data->devid);
        sleep(1);
    }

    return NULL;
}


