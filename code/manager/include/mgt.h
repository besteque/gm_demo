
#ifndef _MGT_H_
#define _MGT_H_


#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <stdint.h>

#include "pub.h"
#include "common.h"


//extern struct list_head      dev_list_head;


int int_device_list(struct list_head *head);
int list_add_device(dev_info_t *info, struct list_head *head);


uint32_t validate_data(int8_t *buf, uint32_t len);
uint32_t handle_login_req(int8_t *buf, uint32_t len);
uint32_t parse_data(int8_t *buf, uint32_t len);
uint32_t handle_login_ack(int8_t **data, uint32_t *len);
uint32_t prepare_interactive_data(uint32_t msg_type, int8_t **data, uint32_t *len);
uint32_t get_key_by_devid(int8_t *dev_id, int8_t *pk);
uint32_t get_devinfo_by_devid(int8_t *dev_id, dev_info_t *info);
uint32_t update_devinfo_by_devid(int8_t *dev_id, dev_info_t *info);




#endif

