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



/***************************************************************
*           functions
****************************************************************/

uint32_t calc_total_len(task_priv_data_t *priv, uint32_t len)
{
    priv->total_rcv_data_len += len;
    return OK;
}

uint32_t get_total_len(task_priv_data_t *task_val)
{
    //uint32_t index;
    //proc_spec_data_t *priv;

    //get_proc_priv_data(&priv);
    //index = get_task_serialno();

    return task_val->total_rcv_data_len;
}


/*
*   1 endian convert  --TODO!!!!!!!!
*   2  free buf when data been sent 
*/
uint32_t send_to_client(uint32_t fd, int8_t *data, uint32_t len)
{
    if (send(fd,data,len,0) < 0)  
    {  
        log_info(MSG_LOG_DBG, SVR, "response_to_client failed.");  
        return ERROR;  
    }

    //dbg_print_char_in_buf(data, len);

    return OK;
}

uint8_t check_cilent_exist(proc_spec_data_t *proc_priv, uint32_t client_ip, uint32_t client_port)
{
    uint32_t i;

    for (i = 0; i < proc_priv->client_num; i++)
    {
        log_info(MSG_LOG_DBG, SVR, "proc_priv->client_info[i].ip:%#x:%x, client_ip:%#x:%x", 
                    proc_priv->client_info[i].ip, proc_priv->client_info[i].port, client_ip, client_port);
    
        if ((proc_priv->client_info[i].ip == client_ip)
             && (proc_priv->client_info[i].port == client_port))
            return BOOL_TRUE;
    }

    return BOOL_FALSE;
}

uint32_t create_monitor_task(pthread_t *taskid, task_priv_data_t *taskval)
{
    int32_t ret;
    //void * tret;
    uint32_t index, i;
    pthread_t task_id;
    proc_spec_data_t *priv;

    get_proc_priv_data(&priv);
    
    ret = pthread_create(taskid, NULL, secure_comm_task, (void*)taskval);
    log_info(MSG_LOG_DBG, SVR, "create_monitor_task pthread_create <taskid:%ld> ret:%d", *taskid, ret);
    
    log_info(MSG_LOG_DBG, SVR, "create_monitor_task priv->client_num:%d", priv->client_num);

    // fill in some import field
    priv->client_info[priv->client_num].task_id = *taskid;
    taskval->task_id = *taskid;
    log_info(MSG_LOG_DBG, SVR, "create_monitor_task *taskid:%ld", *taskid);

#if 0
    /* if run here, task may exit */
    task_id = taskval->task_id;
    ret = pthread_join(task_id, &tret);
    log_info(MSG_LOG_DBG, SVR, "pthread_join ret:%d", ret);
    log_info(MSG_LOG_DBG, SVR, "task exit, id %ld", task_id);

    // free task var data
    for (i = 0; i< MONITOR_THREAD_NUM_MAX; i++)
    {
        if (priv->client_info[i].task_id == task_id)
        {
            priv->client_num--;
            memset(&priv->client_info[i], 0, sizeof(client_info_t));        
        }
    }
#endif
    // auto free, when task exit
    /*if (taskval != NULL)
    {
        free((char*)taskval);
        taskval = NULL;
    }*/

    return ret;
}


/*
*   use "netstat -ntlp" to see port info
*   return: socketfd
*/
uint32_t init_monitor(int8_t *addr, uint32_t port) 
{
    int32_t ret;
    int32_t svr_fd = -1;
    struct sockaddr_in svr_addr;   
    uint32_t sin_size;  
    int8_t   buf[BUFSIZ] = {0};  
    int32_t  flag = 1;     
    int32_t  sock_flags;

    memset(&svr_addr,0,sizeof(svr_addr));
    svr_addr.sin_family = AF_INET; 
    svr_addr.sin_addr.s_addr = (!addr?INADDR_ANY:inet_addr(addr));
    svr_addr.sin_port = htons(port);

    if ((svr_fd = socket(AF_INET,SOCK_STREAM,0))<0)  
    {    
        log_info(MSG_LOG_DBG, SVR, "create socket failed.");  
        return ERROR;  
    }

    /* set socket non-blocking */
    
    sock_flags =      fcntl(svr_fd, F_GETFL, 0);
    ret = fcntl(svr_fd, F_SETFL, sock_flags | O_NONBLOCK);
    
    
    /* when flag!=0, re-use socket fd if exist */
    setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int32_t));
    
    if (bind(svr_fd,(struct sockaddr *)(&svr_addr),sizeof(struct sockaddr))==-1)
    {
        log_info(MSG_LOG_DBG, SVR, "bind error, fd:%d", svr_fd);
        return ERROR;  
    }

    return svr_fd;
}


uint32_t start_monitor(uint32_t svr_fd)
{
    uint32_t sin_size = sizeof(struct sockaddr_in);  
    int32_t  client_fd; 
    struct sockaddr_in client_addr;
    pthread_t th_id = 0;
    proc_spec_data_t *proc_priv;
    uint32_t client_ip;

    if (listen(svr_fd, TCP_CONNECT_POOL) == -1)
    {
        log_info(MSG_LOG_DBG, SVR, "listen error");
        return ERROR;  
    }


    while(1)
    {

        // same client has unique fd, if not closed or timeout
        if((client_fd = accept(svr_fd, (struct sockaddr *)(&client_addr), &sin_size)) == -1)
        {
            //log_info(MSG_LOG_DBG, SVR, "accept error");
            usleep(1000);/* set socket non-blocking */
            continue;
        }
        
        /* 
            for each     transaction, init        counter before       preserve data
            create task, init priv data:task_priv_data_t
            thread id asigned by proc, restrict by MONITOR_THREAD_NUM_MAX
        */
        get_proc_priv_data(&proc_priv);

        // must use client_addr to distinguish socket connection
        client_ip = inet_addr(inet_ntoa(client_addr.sin_addr));
        log_info(MSG_LOG_DBG, SVR, "client %s:%d(%#x) been connected.", 
                            inet_ntoa(client_addr.sin_addr), client_addr.sin_port, client_ip);
        // port = client_addr.sin_port;
        
        
        log_info(MSG_LOG_DBG, DBG, "check_cilent_exist proc_priv->client_num %d", proc_priv->client_num);
        if ((!check_cilent_exist(proc_priv, client_ip, client_addr.sin_port)) && (proc_priv->client_num < MONITOR_THREAD_NUM_MAX))
        {
            proc_priv->task_var[proc_priv->client_num] = (task_priv_data_t *)malloc(sizeof(task_priv_data_t));
            if (proc_priv->task_var[proc_priv->client_num] == NULL)
            {
                log_info(MSG_LOG_DBG, SVR, "oops:memory exhaust.");
                continue;
            }

            /* persist task info */
            // static data
            //proc_priv->client_info[proc_priv->client_num].task_id = *taskid;
            proc_priv->client_info[proc_priv->client_num].cli_sockfd = client_fd;
            proc_priv->client_info[proc_priv->client_num].ip = client_ip;
            proc_priv->client_info[proc_priv->client_num].port = client_addr.sin_port;

            // dynamic data, some field will make-up later, such as taskid
            bzero(proc_priv->task_var[proc_priv->client_num], sizeof(task_priv_data_t));
            proc_priv->task_var[proc_priv->client_num]->cli_sockfd = client_fd;
            proc_priv->task_var[proc_priv->client_num]->client_ip = client_ip;
            proc_priv->task_var[proc_priv->client_num]->client_port = client_addr.sin_port;

            // create task
            create_monitor_task(&th_id, proc_priv->task_var[proc_priv->client_num]);
            
        } 
        else
        {
            log_info(MSG_LOG_DBG, SVR, "create thread child id else branch");
            
            if (proc_priv->client_num >= MONITOR_THREAD_NUM_MAX)
            {
                log_info(MSG_LOG_DBG, SVR, "oops:connection pool exhaust.");
                continue;
            }

            // same client, reset dynamic data
            log_info(MSG_LOG_DBG, SVR, "client %s:%d(%#x) re-connected.", 
                            inet_ntoa(client_addr.sin_addr), client_addr.sin_port, client_ip);
            
            // CAUTION:must substract 1 as index
            proc_priv->task_var[proc_priv->client_num-1]->total_rcv_data_len = 0;
        }
        
    } 

    return OK;
}


uint32_t close_monitor(proc_spec_data_t *proc_data)
{
    int32_t i;
    if(proc_data->sockfd != INVALID_SOCKET_FD)
    {
        close(proc_data->sockfd);        
    }

    pthread_mutex_destroy(&proc_data->dev_mutex);

    //free devlist
    clear_dev_node(&proc_data->dev_list_head);
    
    //free task var --detached, auto free
    /*for (i=0;i<MONITOR_THREAD_NUM_MAX;i++)
    {
        if (proc_data->task_var[i])
        {
            free((char*)proc_data->task_var[i]);
            proc_data->task_var[i] = NULL;
        }
    }*/

    free((char*)proc_data);

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
    int32_t ret, ack_ret;
    uint32_t i;
    void * tret;
    pthread_t task_id;
    int32_t  len = 0;  
    int8_t   buf[BUFSIZ] = {0};       //BUFSIZ=8096
    int8_t   child_name[THREAD_NAME_LEN_MAX];
    //uint32_t index;
    int32_t  client_fd; 
    int8_t   *ack_data = NULL;
    uint32_t ack_len;
    proc_spec_data_t *proc_val;
    task_priv_data_t *task_val = (task_priv_data_t *)priv;

    client_fd = task_val->cli_sockfd;
    get_proc_priv_data(&proc_val);
    log_info(MSG_LOG_DBG, SVR, "[child]task_data->cli_sockfd:%d", task_val->cli_sockfd);
    log_info(MSG_LOG_DBG, SVR, "[child]task_data->client_ip:%d", task_val->client_ip);
    log_info(MSG_LOG_DBG, SVR, "[child]task_data->client_port:%d", task_val->client_port);
    

    // set child name, affirm unique
    snprintf(child_name, THREAD_NAME_LEN_MAX, "Th_%x%x", task_val->client_ip, task_val->client_port);
    prctl(PR_SET_NAME, child_name);

    pthread_detach(pthread_self());
    
    proc_val->client_num++;

    //getsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &stat, (socklen_t *)&len); 
    
    
    // set timer, when task_data.total_rcv_data_len when timeout
    
    while ((len = recv(client_fd, buf, BUFSIZ, 0)) > 0)
    {
        
        log_info(MSG_LOG_DBG, SVR, "recv data len:%ld", len);
    
        if (validate_data(buf, len) != OK)
            continue;
    
        
         /* transaction */         // or EXCEPTION
         ret = parse_data(task_val, buf, len);
        if ((ret == FINISH) || (ret == EXCEPTION))
        {
            ack_ret = prepare_interactive_data(task_val, ((msg_head_t*)buf)->type, &ack_data, &ack_len);
            log_info(MSG_LOG_DBG, SVR, "prepare_interactive_data ret:%d", ack_ret);
            if (ack_ret == OK)
            {                    
                send_to_client(client_fd, ack_data, ack_len);
                log_info(MSG_LOG_DBG, SVR, "send_to_client OK");
            }
            else
            {
                log_info(MSG_LOG_DBG, SVR, "send_err_ack to client.");
                send_err_ack(client_fd, &ack_data);
                //continue;
            }
            
            //log_info(MSG_LOG_DBG, SVR, "data sent to client:%s", ack_data+sizeof(msg_head_t));
            //dbg_print_char_in_buf(ack_data+sizeof(msg_head_t), 64);
    
    
            /* release resources */
            task_val->total_rcv_data_len = 0;
    
            if (ack_data)
            {
                free((char*)ack_data);
                ack_data = NULL;
            }
        }
        
    
        if (ret == OK   )
            log_info(MSG_LOG_DBG, SVR, "wait for next package data");

        memset(buf, 0, BUFSIZ);
    }

    if (client_fd >0)
        close(client_fd);
    
    // need timer, or may cause deadloop


    /* if run here, task may exit */
    task_id = task_val->task_id;
    log_info(MSG_LOG_DBG, SVR, "task exit, id %ld", task_id);

    // free task var data
    for (i = 0; i< MONITOR_THREAD_NUM_MAX; i++)
    {
        if (proc_val->client_info[i].task_id == task_id)
        {
            proc_val->client_num--;
            memset(&proc_val->client_info[i], 0, sizeof(client_info_t));        
        }
    }


    // release resource, and destroy task???
    if (priv)
    {
        free((char*)priv);
        priv = NULL;
    }
    pthread_exit(NULL);

    return NULL;
}


