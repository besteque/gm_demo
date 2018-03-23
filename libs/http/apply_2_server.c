#include <stdio.h>
#include <stdlib.h>
//#include <sys/types.h>
//#include <linux/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include "cJSON.h"
#include "apply_2_server.h"

typedef struct
{
	char *headerSend;
	char *headerReceive;
	char *message;
	long messageLength;
}HTTPRequest;

typedef struct
{
	unsigned char *buffer;
	unsigned char *position;
	int size;
}MemBuffer;

void MemBufferCreate(MemBuffer *b)
{
	//printf("700\n");
	b->size = 100;
	b->buffer = (unsigned char*)malloc(b->size);
	b->position = b->buffer;
}

void MemBufferGrow(MemBuffer *b)
{
	int sz;
	sz = b->position - b->buffer;
	b->size = b->size*2;
	b->buffer = (unsigned char*)realloc(b->buffer,b->size);
	b->position = b->buffer + sz;
}

void MemBufferAddByte(MemBuffer *b,unsigned char byt)
{
	if((int)(b->position - b->buffer) >= b->size)
	{
		MemBufferGrow(b);
	}
	*(b->position++) = byt;
}

void MemBufferAddBuffer(MemBuffer *b,unsigned char *buffer,int size)
{
	while(((int)(b->position - b->buffer) + size ) >= b->size)
	{
		MemBufferGrow(b);
	}
	memcpy(b->position,buffer,size);
	b->position += size;
}

unsigned long GetHostAddress(char *host)
{
	struct hostent *phe;
	//struct in_addr **addr_list;
	char *p,**pp;
	char str[32];
	unsigned long ret;
	phe = gethostbyname(host);
	if(phe == NULL)
		return 0;
/*	pp = phe->h_addr_list;
	if(pp[0] != NULL)
		printf("%s\n",inet_ntop(phe->h_addrtype,*pp,str,sizeof(str)));*/
	p = *phe->h_addr_list;
	ret = *((unsigned long*)p);
	//printf("%ld",ret);
	return 1;
}
void SendString(int sock,char *s)
{
	send(sock,s,strlen(s),0);
}

int SendHTTP(char *header,unsigned char *post,int postlength,HTTPRequest *req)
{
	cJSON *json,*item;
	int cfd,l,chars,rtn;
	struct sockaddr_in s_add;
	unsigned short port = 9011;//80;
	char buffer[300];
	//char host[15]="www.cpksafe.com";
	MemBuffer headerBuffer,messageBuffer;
	//char headerSend[1024];
	unsigned char done;
	cfd = socket(AF_INET,SOCK_STREAM,0);
	if(-1 == cfd)
	{
		printf("socket creat faile!\n");
		return -1;
	}
	bzero(&s_add,sizeof(struct sockaddr_in));
	s_add.sin_family = AF_INET;
	//s_add.sin_addr.s_addr = GetHostAddress("www.cpksafe.com");
	s_add.sin_addr.s_addr = inet_addr("1.202.165.174");//inet_addr("101.201.209.114");//inet_addr("192.168.1.137");
	s_add.sin_port = htons(port);
	if(-1 == connect(cfd,(struct sockaddr *)(&s_add),sizeof(struct sockaddr)))
	{
		printf("connect fail !\n");
		return -1;
	}
	//printf("connect ok\n");

	SendString(cfd,"POST ");
        //strcpy(headerSend,"POST ");
	SendString(cfd,"/cpkdemo/rest/remoteApi/getkeycard");//"/hywd/rest/cloudSpace/copyprotection");
        //strcat(headerSend,"/hywd/rest/cloudSpace/copyprotextion");

	SendString(cfd," HTTP/1.0\r\n");
	//strcat(headerSend," HTTP/1.0\r\n");

	SendString(cfd,"Accept: image/gif, image/x-xbitmap,"
			" image/jpeg, image/pjpeg, application/vnd.ms-excel,"
			" application/msword, application/vnd.ms-powerpoint,"
			" */*\r\n");
	//strcat(headerSend,"Accept: image/gif, image/x-xbitmap, "
		//	" image/jpeg, image/pjpeg, application/vnd.ms-excel,"
			//" application/msword, application/vnd.ms-powerpoint,"
			//" */*\r\n");

	SendString(cfd,"Accept-Language: en-us\r\n");
	//strcat(headerSend,"Accept-Language: en-us\r\n");

	SendString(cfd,"Accept-Encoding: gzip, deflate\r\n");
	//strcat(headerSend,"Accept-Encoding: gzip, deflate\r\n");

	SendString(cfd,"User-Agent: Mozilla/4.0\r\n");
	//strcat(headerSend,"User-Agent: Mozilla/4.0\r\n");

	sprintf(buffer,"Content-Length: %ld\r\n",postlength);
	SendString(cfd,buffer);
	//strcat(headerSend,buffer);

	SendString(cfd,"Host: ");
	//strcat(headerSend,"Host: ");

	SendString(cfd,"1.202.165.174");//"WWW.CPKSAFE.COM");
	//strcat(headerSend,"WWW.CPKSAFE.COM");

	SendString(cfd,"\r\n");
	//strcat(headerSend,"\r\n");

	if((header != NULL) && *header)
	{
		SendString(cfd,header);
		//strcat(headerSend,header);
	}

	SendString(cfd,"\r\n");
	//strcat(headerSend,"\r\n");

    if((post != NULL) && postlength)
	{
		send(cfd,post,postlength,0);
		post[postlength] = '\0';
		//strcat(headerSend,post);
	}

	//req->headerSend = (char*)malloc(sizeof(char*)* strlen(headerSend));
	//strcpy(req->headerSend,(char*)headerSend);
   	//printf("%s",req->headerSend);
	//MemBufferCreate(&headerBuffer);
	done = 0;
	while(!done)
	{
		l = recv(cfd,buffer,1,0);
		if(l < 0)
		{
			done = 1;
		}
		switch(*buffer)
		{
			case '\r':
			   break;
			case '\n':
			   if(chars == 0)
			   {
			   	done = 1;
			   }
			   chars = 0;
			   break;
			default:
			   chars++;
			   break;
		}
		//MemBufferAddByte(&headerBuffer,*buffer);
	}
        //req->headerReceive = (char*)headerBuffer.buffer;
	//*(headerBuffer.position) = 0;

	MemBufferCreate(&messageBuffer);
	do
	{
		l = recv(cfd,buffer,sizeof(buffer)-1,0);
		if(l < 0)
		{
			break;
		}
		*(buffer + l) = 0;
		MemBufferAddBuffer(&messageBuffer,(unsigned char*)&buffer,l);
	}while(l > 0);
	*messageBuffer.position = 0;
	req->message = (char*)messageBuffer.buffer;
	req->messageLength = (messageBuffer.position - messageBuffer.buffer);
	close(cfd);
	return 0;
}

int IW_Sendrequest(char *sn,char *blob,char *p)
{
	cJSON *root,*s1,*s2;
	char *out;
	root = cJSON_CreateObject();
	cJSON_AddItemToObject(root,"userid",cJSON_CreateString(sn));
	cJSON_AddItemToObject(root,"blob",cJSON_CreateString(blob));
	out = cJSON_Print(root);
	cJSON_Delete(root);
	return send_request(out,p);	
}

int send_request(char *s,char *p)
{
	cJSON *json,*item,*item1;
	HTTPRequest req;
	char *buffer;
	int i,rtn;
	unsigned char IsPost = 1;
	req.headerSend = NULL;
	req.headerReceive = NULL;
	req.message = NULL;
	i = strlen(s);
	buffer = (char*)malloc(i+1);
	strcpy(buffer,s);
	rtn = SendHTTP("Content-Type: application/json\r\n",
		(unsigned char*)buffer,
		i,
		&req);
//	printf("%s",req.message);
	json = cJSON_Parse(req.message);
	item = cJSON_GetObjectItem(json,"state");
	if(!strcmp(item->valuestring,"OK"))
	{
		item = cJSON_GetObjectItem(json,"data");
		item = cJSON_GetObjectItem(item,"envelope");
		strcpy(p,item->valuestring);
		rtn = 0;
	}
	else
	{
		item = cJSON_GetObjectItem(json,"errorcode");
		rtn = item->valueint;
		item = cJSON_GetObjectItem(json,"msg");
		strcpy(p,item->valuestring);
	}

	cJSON_Delete(json);
	return rtn;
}

/*void main()
{
	char out[1024];
	IW_Sendrequest("000000000260","AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAz9D44To9eUenFWv8IDSjxZPjO9sJYmaNa7zLbWC4H+gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH7AjaqpPBP+F6/BqZLKmrjr+KCcpc3S6Z2jr6msNzoA",out);
	printf("haha : %s",out);
}*/
