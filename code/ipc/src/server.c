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
uint32_t    total_rcv_data_len = 0;
uint8_t     session_id[DEV_ID_LEN_MAX] = {0};   // in multi-thread scene, each thread has a session_id




/***************************************************************
*           functions
****************************************************************/
void init_session_data(void)
{
    total_rcv_data_len = 0;
    session_id[0] = '\0';
}


uint32_t calc_total_len(uint32_t len)
{
    total_rcv_data_len += len;
    return OK;
}

uint32_t get_total_len(void)
{

    return total_rcv_data_len;
}


/* free buf when data been sent */
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

    uint32_t svr_fd;
    struct sockaddr_in svr_addr;   
    uint32_t sin_size;  
    uint8_t buf[BUFSIZ] = {0};  

    memset(&svr_addr,0,sizeof(svr_addr));
    svr_addr.sin_family = PF_INET; 
    svr_addr.sin_addr.s_addr = (!addr?INADDR_ANY:inet_addr(addr));
    svr_addr.sin_port = htons(port);

    if ((svr_fd = socket(PF_INET,SOCK_STREAM,0))<0)  
    {    
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "create socket failed.");  
        return ERROR;  
    }  

    if (bind(svr_fd,(struct sockaddr *)(&svr_addr),sizeof(struct sockaddr))==-1)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "bind error");
        return ERROR;  
    }

    return svr_fd;
}


uint32_t start_monitor(uint32_t svr_fd)
{
    uint32_t len;  
    uint32_t sin_size = sizeof(struct sockaddr_in);  
    uint32_t client_fd; 
    int8_t   buf[BUFSIZ]; 
    int8_t   *ack_data;
    uint32_t ack_len;
    struct sockaddr_in client_addr;

    if (listen(svr_fd,5) == -1)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "listen error");
        return ERROR;  
    }


    while(1)
    {
        if((client_fd = accept(svr_fd, (struct sockaddr *)(&client_addr), &sin_size)) == -1)
        {
            PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "listen error");
            continue;
        }

        /* for each     transaction, init        counter before       preserve data     */
        init_session_data();
        
        PRINT_SYS_MSG(MSG_LOG_DBG, SVR, "client %s been connected.", inet_ntoa(client_addr.sin_addr));

        //getsockopt(SOCKET_HANDLE ,SOL_SOCKET,SO_SNDBUF, ...);
        
        while((len = recv(client_fd, buf, BUFSIZ, 0)) > 0)
        {
        
            if (validate_data(buf, len) != OK)
                continue;

            
             /* transaction */
            if (parse_data(buf, len) == FINISH)
            {
                prepare_interactive_data(((msg_head_t*)buf)->type, &ack_data, &ack_len);
                send_to_client(client_fd, ack_data, ack_len);


                /* release resources */
                close(client_fd);
                free(ack_data);
                break;
            }

            // need timer, or may cause deadloop
        } 
    }

    return OK;
}


uint32_t close_monitor(uint32_t svr_fd)
{
    if(svr_fd != INVALID_SOCKET_FD)        
        close(svr_fd);

    return OK;
}


