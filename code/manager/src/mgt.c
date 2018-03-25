/*
 * mgt.c
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */
    
#include "crypt.h"
#include "mgt.h"






int int_device_list(struct list_head *head)
{
    INIT_LIST_HEAD(head);
}

int list_add_device(dev_info_t *info, struct list_head *head)
{
    proc_spec_data_t *priv;
    struct list_head *pos;
    dev_info_t      *dev;
    dev_info_t      *node;
    uint32_t index;

    
    if (list_empty(head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "devlist empty, create it");
        goto ADD_LIST;
    }

     list_for_each(pos, head)
    {
        dev = list_entry(pos, dev_info_t, point);

        if (!strncmp(dev->id, info->id, strlen(info->id)))
        {
            return OK;
        }
    }

ADD_LIST:
    get_proc_priv_data(&priv);
    index = get_task_serialno();    
    strncpy(priv->task_var[index]->devid, info->id, strlen(info->id));

    /*****************************************************************************
    * WARNing: new node must apply heap memeroy! stack will recycle after return
    ******************************************************************************/
    node = malloc(sizeof(dev_info_t));
    memcpy(node, info, sizeof(dev_info_t));
    
    list_add(&node->point, head);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "add node OK");
    
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
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "msg_head magic incorrect: %s", head.magic);
        return ERROR;
    }

    if (head.type > MAX_MSG_TYPE)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "msg_head type %d unrecognized", head.type);
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
    login_data_t        log_data;
    dev_info_t          devinfo = {0};
    proc_spec_data_t *priv;

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(log_data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "len != (sizeof(msg_head) + sizeof(log_data))");
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));
    memcpy(&log_data, msg+sizeof(head), sizeof(log_data));

    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "rcv msgid:%#x, devid:%s", head.type, log_data.dev_id);
    
    get_proc_priv_data(&priv);

    strncpy(devinfo.id, log_data.dev_id, strlen(log_data.dev_id));
    list_add_device(&devinfo, &priv->dev_list_head);
    
    //strncpy(devnode.id, log_data.dev_id, strlen(log_data.dev_id));
    

    // stub
    dbg_print_dev_list(&priv->dev_list_head);

    return OK;
}



uint32_t handle_signiture_req(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    signiture_data_t         sign_data;
    dev_info_t          devinfo = {0};
    int8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(sign_data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "handle_signiture_req:len != (sizeof(msg_head) + sizeof(sign_data))");
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));
    memcpy(&sign_data, msg+sizeof(head), sizeof(sign_data));

    // stub
    //dbg_print_dev_list(&dev_list_head);

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);

    //devnode.sign_data = sign_data;

    // need decrypt ????
    //ret = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);

    // save data
    memcpy(&devinfo.sign_data, &sign_data, sizeof(signiture_data_t));
    update_devinfo_by_devid(devid, &devinfo);
    
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "client %s sign data:%s", devid, sign_data.data);

    return OK;
}


uint32_t negotiate_crypt_type(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    encrypt_data_t         crypt_data;
    dev_info_t          devinfo = {0};
    int8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    if (len != (sizeof(head) + sizeof(crypt_data)))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "negotiate_crypt_type:len != (sizeof(msg_head) + sizeof(crypt_data))");
        return ERROR;
    }

    memcpy(&head, msg, sizeof(head));
    memcpy(&crypt_data, msg+sizeof(head), sizeof(crypt_data));

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);
    //devnode.crypt_type = crypt_data;


    // need decrypt ????
    //ret = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);

    // save data
    memcpy(&devinfo.crypt_type, &crypt_data, sizeof(encrypt_data_t));
    update_devinfo_by_devid(devid, &devinfo);
    
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "dev %s affirmed crypt type:%#x", devid, crypt_data.algorithm);

    return OK;
}



uint32_t rcv_usr_data(int8_t *msg, uint32_t len)
{
    msg_head_t          head;
    dev_info_t          devinfo = {0};
    int8_t devid[DEV_ID_LEN_MAX] = {0};

    // multi-pkg todo...

    memcpy(&head, msg, sizeof(head));

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);
    //devinfo = devnode;


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
    int32_t ret = OK, index;
    msg_head_t head;
    proc_spec_data_t *priv;

    memcpy(&head, msg, sizeof(head));
    //PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "svr rcv msgid %#x", head.type);
    dbg_print_msg_head(&head);

    switch (head.type)
    {
        case MSG_TYPE_LOGIN:
            ret = handle_login_req(msg, len);
            break;

        
        case MSG_TYPE_SIGNITURE:
            ret = handle_signiture_req(msg, len);
            break;
            
        case MSG_TYPE_ENCRYPT_INFO:
            ret = negotiate_crypt_type(msg, len);
            break;
            
        case MSG_TYPE_USR_DATA:

            // todo!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

            //msg null, do not free it
            ret = ERROR; 

            break;

        default:break;
    }


    if (ret != OK)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "parse_data failed, ret:%d", ret);
        return ERROR;
    }

    // need adapt, use original data_len
    get_proc_priv_data(&priv);
    index = get_task_serialno();
    calc_total_len(priv->task_var[index], head.data_len);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "receive data total len:%ld, expect:%ld", 
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
    proc_spec_data_t *proc;

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

    get_proc_priv_data(&proc);

    login_data = (login_data_t*)((msg_head_t*)buf +1);
    memcpy(login_data->dev_id, proc->devid, strlen(proc->devid));
    
    
}


uint32_t handle_sign_ack(int8_t **data, uint32_t *len)
{
    int32_t ret;
    int8_t      *buf;
    uint32_t    data_len;
    msg_head_t *head;
    signiture_data_t *sign_data;
    dev_info_t          devinfo = {0};
    int8_t devid[DEV_ID_LEN_MAX] = {0};
    int8_t sign_val[SIGN_DATA_LEN_MAX] = {0};

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
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "handle_sign_ack devid:%s", devid);
    get_devinfo_by_devid(devid, &devinfo);
    
    //dbg_print_char_in_buf(devinfo.sign_data.data, SIGN_DATA_LEN_MAX);
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "original data:%s", devinfo.sign_data.data);

    // encrypt according Base64
    ret = IW_ServerSignData(devinfo.sign_data.data, sign_val);
    if (ret != OK)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "IW_ServerSignData failed, code %d");
        return ERROR;
    }
    PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "ret code %d, after sign:%s", ret, sign_val);
    /////PRINT_SYS_MSG(MSG_LOG_DBG, MGT, "devid:%s, sign ret:%#x", devid, ret);

    dbg_print_devinfo(&devinfo);
    
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
    int8_t devid[DEV_ID_LEN_MAX] = {0};

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
    head->type = MSG_TYPE_ENCRYPT_INFO;
    head->data_len = sizeof(encrypt_data_t);
    head->total_length = head->data_len;
    head->total_package = 1;
    strncpy(head->magic, MAGIC_WORD, MAGIC_WORD_LEN_MAX);

    get_dev_id(devid);
    get_devinfo_by_devid(devid, &devinfo);    
    //devinfo = devnode;

    crypt_data = (encrypt_data_t*)((msg_head_t*)buf +1);
    
    // need encrypt whole data 'devinfo.crypt_type', then asign to 'crypt_data' ?
    memcpy(crypt_data, &devinfo.crypt_type, sizeof(encrypt_data_t));

    return OK;
    
}



/**
 * response data to TE
*/

uint32_t prepare_interactive_data(uint32_t msg_type, int8_t **data, uint32_t *len)
{
    int32_t ret;

    switch (msg_type)
    {
        case MSG_TYPE_LOGIN:
            ret = handle_login_ack(data, len);
            break;

        
        case MSG_TYPE_SIGNITURE:
            ret = handle_sign_ack(data, len);
            break;
            
        case MSG_TYPE_ENCRYPT_INFO:
            ret = affirm_crypt_type(data, len);
            break;
            
        case MSG_TYPE_USR_DATA:

            break;
    }

    if (ret != OK)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "prepare_interactive_data failed, ret:%d", ret);
        return ret;
    }

    return OK;
}



/* 
    get comm key by device id  
*/
uint32_t get_key_by_devid(int8_t *dev_id, int8_t *pk)
{
    proc_spec_data_t * priv = NULL;
    struct list_head *pos, *n;
    dev_info_t      *dev;

    get_proc_priv_data(&priv);

    if (list_empty(&priv->dev_list_head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "list dev_list_head is empty");
        return ERROR;
    }

     list_for_each_safe(pos, n, &priv->dev_list_head)
    {
        dev = list_entry(pos, dev_info_t, point);

        if (!strncmp(dev->id, dev_id, strlen(dev_id)))
        {
            strncpy(pk, dev->crypt_type.key, strlen(dev->crypt_type.key));
            return OK;
        }
    }

    return ERROR;
}



/* 
    get devinfo by device id
    INT1:dev_id
    OUT1:info
*/
uint32_t get_devinfo_by_devid(int8_t *dev_id, dev_info_t *info)
{
    proc_spec_data_t * priv = NULL;
    struct list_head *pos;
    dev_info_t      *dev;

    get_proc_priv_data(&priv);

    if (list_empty(&priv->dev_list_head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "list dev_list_head is empty");
        return ERROR;
    }

     list_for_each(pos, &priv->dev_list_head)
    {
        dev = list_entry(pos, dev_info_t, point);

        if (dev == NULL)
        {
            PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "error, list is null");
            return ERROR;
        }

        if (!strncmp(dev->id, dev_id, strlen(dev_id)))
        {
            memcpy(info, dev, sizeof(*dev));
            return OK;
        }
    }
    
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "error, get_devinfo_by_devid failed");

    return ERROR;
}


/*
    update devnode
    IN1:dev_id
    IN2:info
*/
uint32_t update_devinfo_by_devid(int8_t *dev_id, dev_info_t *info)
{
    proc_spec_data_t * priv = NULL;
    struct list_head *pos;
    dev_info_t      *dev;

    get_proc_priv_data(&priv);

    if (list_empty(&priv->dev_list_head))
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "list dev_list_head is empty");
        return ERROR;
    }

     list_for_each(pos, &priv->dev_list_head)
    {
        dev = list_entry(pos, dev_info_t, point);

        if (dev == NULL)
        {
            PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "error, list is null");
            return ERROR;
        }

        if (!strncmp(dev->id, dev_id, strlen(dev_id)))
        {
            memcpy(dev, info, sizeof(dev_info_t));
            return OK;
        }
    }
    
    PRINT_SYS_MSG(MSG_LOG_DBG, INIT, "error, update_devinfo_by_devid failed");

    return ERROR;
}


