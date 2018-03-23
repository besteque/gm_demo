/*
 * mgt.c
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */

#include "mgt.h"




int int_device_list(list_t *head)
{
    INIT_LIST_HEAD(head);
}

int list_add_device(dev_info_t *info, list_t *head)
{
    list_t *pos;
    dev_info_t      *dev;

    
    if (list_empty(&dev_list_head))
        goto ADD_LIST;

    list_for_each(pos, head)
    {
        dev = list_entry(pos, dev_info_t, member);

        if (!strncmp(dev->id, info->id, strlen(info->id)))
        {
            return OK;
        }
    }

ADD_LIST:
    record_dev_id(info->id);
    list_add(&info->member, head);
    
    return OK;
}


uint32_t validate_data(int8_t *buf, uint32_t len)
{
    msg_head_t head;
    

    if (len < sizeof(head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len(%d) < sizeof(msg_head)(%ld)", len, sizeof(head));
        return ERROR;
    }

    memcpy(&head, buf, sizeof(head));

    if (strncmp(head.magic, MAGIC_WORD, strlen(MAGIC_WORD)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "msg_head.magic %s", head.magic);
        return ERROR;
    }

    if (head.type > MAX_MSG_TYPE)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "msg_head.type %d invalid", head.type);
        return ERROR;
    }

    return OK;
}


/*
    preserve TE device info in a list
*/
uint32_t handle_login_req(int8_t *buf, uint32_t len)
{
    msg_head_t          head;
    login_data_t        data;
    dev_info_t          devinfo = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len != (sizeof(msg_head) + sizeof(data))");
        return ERROR;
    }

    memcpy(&head, buf, sizeof(head));
    memcpy(&data, buf+sizeof(head), sizeof(data));

    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "rcv msgid:%#x, devid:%s", head.type, data.dev_id);

    memcpy(devinfo.id, data.dev_id, DEV_ID_LEN_MAX);
    list_add_device(&devinfo, &dev_list_head);    
    

    return OK;
}



uint32_t handle_signiture_req(int8_t *buf, uint32_t len)
{
    int32_t ret;
    msg_head_t          head;
    signiture_data_t         data;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len != (sizeof(msg_head) + sizeof(data))");
        return ERROR;
    }

    memcpy(&head, buf, sizeof(head));
    memcpy(&data, buf+sizeof(head), sizeof(data));


    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);

    char pSignaturefinal[512] = { 0 };
    //ret = IW_ServerSignData(pSignature, pSignaturefinal);
    //printf("IW_ServerSignData rv is %d\n", rv);
    //printf("数字签名(rv = 0：成功) rv = %d\n被签名数据：%s\n签名值：%s\n", rv, testData, pSignaturefinal);

    
    

    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "rcv msgid:%#x", head.type);



    return OK;
}



uint32_t parse_data(int8_t *buf, uint32_t len)
{
    msg_head_t head;

    memcpy(&head, buf, sizeof(head));
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "svr rcv msgid %#x", head.type);

    switch (head.type)
    {
        case MSG_TYPE_LOGIN:
            handle_login_req(buf, len);
            break;

        
        case MSG_TYPE_SIGNITURE:
            handle_signiture_req(buf, len);
            break;
            
        case MSG_TYPE_ENCRYPT_INFO:

            break;
            
        case MSG_TYPE_USR_DATA:

            break;

        default:break;
    }


    // need adapt, use decrypte data_len
    calc_total_len(head.data_len);
    if (get_total_len() >= head.total_length)
    {
        return FINISH;
    }

    return OK;
}



uint32_t handle_login_ack(int8_t **data, uint32_t *len)
{
    int8_t      *buf;
    uint32_t    data_len;
    msg_head_t *head;
    login_data_t *login_data;
    uint8_t *devid = "id9527";          // stub

    data_len = sizeof(msg_head_t) + sizeof(login_data_t);

    buf = malloc(data_len);
    if (buf == NULL)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "malloc failed");
        return ERROR;
    }

    memset(buf, 0, data_len);

    *len = data_len;
    *data = buf;

    head = (msg_head_t*)buf;
    head->type = MSG_TYPE_LOGIN;
    head->data_len = sizeof(login_data_t);
    head->total_length = head->data_len;
    head->total_package = 1;
    strncpy(head->magic, MAGIC_WORD, MAGIC_WORD_LEN_MAX);


    login_data = (login_data_t*)((msg_head_t*)buf +1);
    memcpy(login_data->dev_id, devid, strlen(devid));
    
    
}


uint32_t prepare_interactive_data(uint32_t msg_type, int8_t **data, uint32_t *len)
{

    switch (msg_type)
    {
        case MSG_TYPE_LOGIN:
            handle_login_ack(data, len);
            break;

        
        case MSG_TYPE_SIGNITURE:

            break;
            
        case MSG_TYPE_ENCRYPT_INFO:

            break;
            
        case MSG_TYPE_USR_DATA:

            break;
    }


    return OK;
}



/* 
    get public key by device id  
*/
uint32_t get_key_by_devid(uint8_t *dev_id, int8_t *pk)
{
    list_t *pos;
    dev_info_t      *dev;

    if (list_empty(&dev_list_head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "list dev_list_head is empty");
        return ERROR;
    }

    list_for_each(pos, &dev_list_head)
    {
        dev = list_entry(pos, dev_info_t, member);

        if (!strncmp(dev->id, dev_id, strlen(dev_id)))
        {
            strncpy(pk, dev->com_key, strlen(dev->com_key));
            return OK;
        }
    }

    return ERROR;
}



/* 
    get devinfo by device id  
*/
uint32_t get_devinfo_by_devid(uint8_t *dev_id, dev_info_t *info)
{
    list_t *pos;
    dev_info_t      *dev;

    if (list_empty(&dev_list_head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "list dev_list_head is empty");
        return ERROR;
    }

    list_for_each(pos, &dev_list_head)
    {
        dev = list_entry(pos, dev_info_t, member);

        if (!strncmp(dev->id, dev_id, strlen(dev_id)))
        {
            memcpy(info, dev, sizeof(*dev));
            return OK;
        }
    }

    return ERROR;
}



