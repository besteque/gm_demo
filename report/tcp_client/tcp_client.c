#include <stdlib.h>
#include <stdio.h>  
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  

#include "pub.h"


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


/* gcc -o tcpclient tcp_client.c pub.h */  
int main(int argc, char *argv[])
{  
    int client_sockfd;  
    int i = 0, len, data_len;  
    struct sockaddr_in remote_addr; //服务器端网络地址结构体  
    char buf[BUFSIZ];  //数据传送的缓冲区
    struct timeval      timeout;
    
    memset(&remote_addr,0,sizeof(remote_addr)); //数据初始化--清零  
    remote_addr.sin_family = AF_INET; //设置为IP通信  
    remote_addr.sin_addr.s_addr = inet_addr("192.168.123.192");//服务器IP地址  
    remote_addr.sin_port = htons(SVR_LISTEN_PORT_NUM); //服务器端口号  
      
    /*创建客户端套接字--IPv4协议，面向连接通信，TCP协议*/  
    if((client_sockfd=socket(PF_INET,SOCK_STREAM,0))<0)  
    {  
        perror("socket");  
        return 1;  
    }  
      
    /*将套接字绑定到服务器的网络地址上*/  
    if(connect(client_sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr))<0)  
    {  
        perror("connect");  
        return 1;  
    }  
    printf("connected to server 192.168.123.192 OK\n");  
    
    //len=recv(client_sockfd,buf,BUFSIZ,0);//接收服务器端信息  
    //buf[len]='\0';  
    //printf("%s",buf); //打印服务器端信息  

    // ack timer
    timeout.tv_sec  = 3;    
    timeout.tv_usec = 0;
    setsockopt(client_sockfd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (char*)&timeout,
                sizeof(struct timeval));
  
    /*循环的发送接收信息并打印接收信息--recv返回接收到的字节数，send返回发送的字节数*/  
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
    
    close(client_sockfd);//关闭套接字  
    
    return 0;  
}  

