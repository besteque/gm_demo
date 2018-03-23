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


uint32_t validate_data(int8_t *msg, uint32_t len)
{
    msg_head_t head;
    

    if (len < sizeof(head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len(%d) < sizeof(msg_head)(%ld)", len, sizeof(head));
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));

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
uint32_t handle_login_req(int8_t *msg, uint32_t len)
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

    memcpy(&head, msg, sizeof(head));
    memcpy(&data, msg+sizeof(head), sizeof(data));

    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "rcv msgid:%#x, devid:%s", head.type, data.dev_id);

    memcpy(devinfo.id, data.dev_id, DEV_ID_LEN_MAX);
    list_add_device(&devinfo, &dev_list_head);    
    

    return OK;
}



uint32_t handle_signiture_req(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    signiture_data_t         sign_data;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(sign_data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len != (sizeof(msg_head) + sizeof(data))");
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));
    memcpy(&sign_data, msg+sizeof(head), sizeof(sign_data));


    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);


    // need decrypt ????
    //ret = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);

    // save data
    memcpy(&devinfo.sign_data, &sign_data, sizeof(signiture_data_t));
    
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "dev %s sign data:%s", devid, sign_data.data);

    return OK;
}


uint32_t negotiate_crypt_type(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    encrypt_data_t         crypt_data;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(crypt_data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len != (sizeof(msg_head) + sizeof(data))");
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));
    memcpy(&crypt_data, msg+sizeof(head), sizeof(crypt_data));


    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);


    // need decrypt ????
    //ret = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);

    // save data
    memcpy(&devinfo.crypt_type, &crypt_data, sizeof(encrypt_data_t));
    
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "dev %s affirmed crypt type:%#x", devid, crypt_data.algorithm);

    return OK;
}



uint32_t rcv_usr_data(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    memcpy(&head, msg, sizeof(head));

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);


    // need decrypt ????
    //ret = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);

    // usr data
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "rcv dev %s usr data", devid);
    dbg_print_msg_head(&head);

    return OK;
}




/**
*   deal TE request data
*/
uint32_t parse_data(int8_t *msg, uint32_t len)
{
    msg_head_t head;

    memcpy(&head, msg, sizeof(head));
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "svr rcv msgid %#x", head.type);

    switch (head.type)
    {
        case MSG_TYPE_LOGIN:
            handle_login_req(msg, len);
            break;

        
        case MSG_TYPE_SIGNITURE:
            handle_signiture_req(msg, len);
            break;
            
        case MSG_TYPE_ENCRYPT_INFO:
            negotiate_crypt_type(msg, len);
            break;
            
        case MSG_TYPE_USR_DATA:

            break;

        default:break;
    }


    // need adapt, use original data_len
    calc_total_len(head.data_len);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "receive data total len:%ld, need:%ld", 
                         get_total_len(), head.total_length);
        
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


uint32_t handle_sign_ack(int8_t **data, uint32_t *len)
{
    int32_t ret;
    int8_t      *buf;
    uint32_t    data_len;
    msg_head_t *head;
    signiture_data_t *sign_data;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};
    uint8_t sign_val[SIGN_DATA_LEN_MAX] = {0};

    data_len = sizeof(msg_head_t) + sizeof(signiture_data_t);

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
    head->type = MSG_TYPE_SIGNITURE;
    head->data_len = sizeof(signiture_data_t);
    head->total_length = head->data_len;
    head->total_package = 1;
    strncpy(head->magic, MAGIC_WORD, MAGIC_WORD_LEN_MAX);

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);

    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "original data:%s", devinfo.sign_data.data);
    ret = IW_ServerSignData(devinfo.sign_data.data, sign_val);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "devid:%s, sign ret:%#x", devid, ret);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "sign data:%s", sign_val);

    sign_data = (signiture_data_t*)((msg_head_t*)buf +1);

    // need encrypt whole sign data 'sign_val', then asign to 'sign_data' ?
    
    memcpy(sign_data->data, sign_val, strlen(sign_val));

    return OK;
    
}


uint32_t affirm_crypt_type(int8_t **data, uint32_t *len)
{
    int32_t ret;
    int8_t      *buf;
    uint32_t    data_len;
    msg_head_t *head;
    encrypt_data_t *crypt_data;
    dev_info_t          devinfo = {0};
    uint8_t devid[DEV_ID_LEN_MAX] = {0};

    data_len = sizeof(msg_head_t) + sizeof(encrypt_data_t);

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
    head->type = MSG_TYPE_SIGNITURE;
    head->data_len = sizeof(encrypt_data_t);
    head->total_length = head->data_len;
    head->total_package = 1;
    strncpy(head->magic, MAGIC_WORD, MAGIC_WORD_LEN_MAX);

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);

    crypt_data = (encrypt_data_t*)((msg_head_t*)buf +1);
    
    // need encrypt whole data 'devinfo.crypt_type', then asign to 'crypt_data' ?
    memcpy(crypt_data, &devinfo.crypt_type, sizeof(encrypt_data_t));

    return OK;
    
}



/**
*    response data to TE
*/

uint32_t prepare_interactive_data(uint32_t msg_type, int8_t **data, uint32_t *len)
{

    switch (msg_type)
    {
        case MSG_TYPE_LOGIN:
            handle_login_ack(data, len);
            break;

        
        case MSG_TYPE_SIGNITURE:
            handle_sign_ack(data, len);
            break;
            
        case MSG_TYPE_ENCRYPT_INFO:
            affirm_crypt_type(data, len);
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



