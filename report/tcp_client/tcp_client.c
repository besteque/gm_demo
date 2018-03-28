/*
 * tcp_client.c
 *
 *  Created on: 2018-3-23
 *      Author: xuyang
 */

#include <stdlib.h>
#include <stdio.h>  
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  

#include "pub.h"


#define SERVER_IP_ADDR             "192.168.0.107"     //aliyun:"116.62.137.197"   pc:"192.168.0.107"


int send_to_server(int setp, char *buf, int buf_len, int *data_len)
{
    msg_head_t head;
    login_data_t log_data;
    signiture_data_t sign_data;
    encrypt_data_t crypt_data;
    char *sign = "rZjSXHcOFIsjN1x0sVG6a6crXrZjSXHcOFIsjN1x0sVG6a6crXrZjSXHcOFIsjN1x0sVG6a6crX";
    
    head.type = setp;
    head.total_package = 1;
    strncpy(head.magic, MAGIC_WORD, MAGIC_WORD_LEN_MAX);


    switch (setp)
    {
        case 1:
        {
            head.data_len = sizeof(login_data_t);
            head.total_length = head.data_len;
            
            sprintf(log_data.dev_id, "%s_%ld", "xuyang", random());
            *data_len = sizeof(head) + sizeof(login_data_t);
            
            memcpy(buf, &head, sizeof(head));
            memcpy(buf+sizeof(head), &log_data, sizeof(log_data));
            break;
        }
        case 2:
        {
            head.data_len = sizeof(signiture_data_t);
            head.total_length = head.data_len;

            strncpy(sign_data.data, sign, strlen(sign));
            *data_len = sizeof(head) + sizeof(signiture_data_t);
            
            memcpy(buf, &head, sizeof(head));
            memcpy(buf+sizeof(head), &sign_data, sizeof(sign_data));
            break;
        }
        case 3:
        {
            head.data_len = sizeof(encrypt_data_t);
            head.total_length = head.data_len;
            
            *data_len = sizeof(head) + sizeof(encrypt_data_t);
            
            memcpy(buf, &head, sizeof(head));
            memcpy(buf+sizeof(head), &crypt_data, sizeof(crypt_data));

            break;
        }
        case 4:
        {
            head.data_len = sizeof(msg_context_t);
            head.total_length = head.data_len;

            //data
            *data_len = sizeof(head) + 100;
            
            memcpy(buf, &head, sizeof(head));
            //fill data
            
            break;
        }

        default:break;

    }
    
    return 0;
}

int rcv_from_server(int setp, char *buf, int buf_len, int *data_len)
{

    return 0;
}

// 根据域名查询ip地址
int get_domain_iaddr(char *domain)
{
    return 0;
}


/* gcc -o tcpclient  pub.h tcp_client.c */  
int main(int argc, char *argv[])
{  
    char server_addr[16] = {0};
    int client_sockfd;  
    int i = 0, len, data_len;  
    struct sockaddr_in remote_addr; 
    char buf[BUFSIZ];       //BUFSIZ=8096
    struct timeval      timeout;

    if (argc < 2)
    {
        printf("server ip not input, use %s as default.\n", SERVER_IP_ADDR);
        strcpy(server_addr, SERVER_IP_ADDR);
    }
    else
    {
        if (strlen(argv[1]) <7)
        {
            printf("server ip %s illegal.\n", argv[1]);
            return -1;
        }
        printf("server ip %s\n", argv[1]);
        strcpy(server_addr, argv[1]);
    }
        
    
    memset(&remote_addr,0,sizeof(remote_addr));
    remote_addr.sin_family = AF_INET; //set ip protocol family
    remote_addr.sin_addr.s_addr = inet_addr(server_addr);
    remote_addr.sin_port = htons(SVR_LISTEN_PORT_NUM); 
      
    /* ipv4 tcp protocol */  
    if((client_sockfd=socket(PF_INET,SOCK_STREAM,0))<0)  
    {  
        perror("socket");  
        return 1;  
    }
    if(connect(client_sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr))<0)  
    {  
        perror("connect");  
        return 1;  
    }  
    printf("connected to server %s OK\n", server_addr);

    // ack timer
    timeout.tv_sec  = 3;    
    timeout.tv_usec = 0;
    setsockopt(client_sockfd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (char*)&timeout,
                sizeof(struct timeval));
  
    while(1)  
    {
        //step
        i++;
        
        send_to_server(i, buf, BUFSIZ, &data_len);
        len = send(client_sockfd, buf, data_len, 0);  
        printf("step %d send OK, date len:%d\n",i, len);          
        
        len = recv(client_sockfd, buf, BUFSIZ, 0);
        rcv_from_server(i, buf, BUFSIZ, &data_len);
        printf("step %d receive OK, date len:%d\n",i, len);

        if (i==4)
            break;
    }  
    
    close(client_sockfd);
    
    return 0;  
}  

