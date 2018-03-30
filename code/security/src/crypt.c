/*
 * crypt.c
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */

#include "crypt.h"



/* init sw-shield, return svr temp pk  

    IN1:dev_id
    OUT1:key
*/
uint32_t init_sw_shield(int8_t *dev_id, int8_t *pkey)
{
    int32_t  ret;
    int32_t  id_len;
    int8_t   usr_id[DEV_ID_LEN_MAX] = {0}; 
    int8_t   tmp_key[PUB_KEY_LEN_MAX] = {0};
    proc_spec_data_t *priv;
    

    if (!dev_id ||!*dev_id || strlen(dev_id)>DEV_ID_LEN_MAX)
    {
        log_info(MSG_LOG_DBG, CRYPT, "device id illegal.");
        return ERROR;
    }

    ret = IW_OpenDevice(dev_id, IWALL_SVKD_REPO); 
    if (ret != OK)
    {
        // SVKD_OPEN_FAIL = 17003
        log_info(MSG_LOG_DBG, CRYPT, "IW_OpenDevice ret:%ld. maybe usr not exist(code:17003)", ret);
        goto APPL_KEY;
    }
    
    ret = IW_ReadKeyID(usr_id, &id_len);
    
    if (ret == OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "svkd usr_id:%s, usr_id:%s", usr_id, dev_id);
        if (!strncmp(dev_id, usr_id, id_len))
        {
            return OK;
        }
    }
    
    // SVKD_ID_VOID = 17005
    log_info(MSG_LOG_DBG, CRYPT, "IW_ReadKeyID code:%ld", ret);


APPL_KEY:
    ret = IW_InitDevice(dev_id, IWALL_SVKD_REPO);
    
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "IW_InitDevice failed, ret = %ld", ret);
        return ERROR;
    }

    /* open dev */
    ret = IW_OpenDevice(dev_id, IWALL_SVKD_REPO);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "IW_OpenDevice failed, ret = %ld", ret);
        return ERROR;
    }    
    log_info(MSG_LOG_DBG, CRYPT, "IW_InitDevice OK");

    /* gene temporary key-pair */
    log_info(MSG_LOG_DBG, CRYPT, "generate temporary key-pair begin");
    ret = IW_GenKeyRequest(dev_id, tmp_key);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "IW_GenKeyRequest failed, ret = %ld", ret);
        return ERROR;
    }    
    
    log_info(MSG_LOG_DBG, CRYPT, "generate temporary key-pair OK");
    log_info(MSG_LOG_DBG, CRYPT, "\"%s\"'s pk is %s", dev_id, tmp_key);

    strncpy(pkey, tmp_key, strlen(tmp_key));
    
    /* apply and preserve secret kety */
    log_info(MSG_LOG_DBG, CRYPT, "get secret key from sk-center");
    ret = persist_secret_key(dev_id, tmp_key);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "get secret key from sk-center failed, code:%ld", ret);
        return ERROR;
    }    
    log_info(MSG_LOG_DBG, CRYPT, "get secret key from sk-center OK");

    /* generate key matrix */
    /*
    log_info(MSG_LOG_DBG, CRYPT, "gene_key_matrix begin");
    get_proc_priv_data(&priv);
    ret = gene_key_matrix(priv->pub_matrix, priv->skey_matrix);
    if (ret != OK)
    {
        log_info(MSG_LOG_DBG, CRYPT, "gene_key_matrix failed, code:%ld", ret);
        return ERROR;
    }    
    log_info(MSG_LOG_DBG, CRYPT, "gene_key_matrix OK");

    */

    return OK;
}


/**
 *    save secret key that recv from sk-center
 *    TE need execute /data/start_data.sh to generate data/libecm and ifport
 *        /data/libecm
 *        /data/start_data.sh
*/
uint32_t persist_secret_key(int8_t *dev_id, int8_t *pkey)
{
    int32_t ret;
    int8_t  secret_key[SECRET_KEY_LEN_MAX] = { 0 };   // device sk
    uint32_t key_len;
    
    // need open dev ? all disappointed
    //ret = IW_OpenDevice(dev_id, IWALL_SVKD_REPO);
    //log_info(MSG_LOG_DBG, CRYPT, "open sw-shield ret = %#x", ret);
    
    ret = IW_Sendrequest(dev_id, pkey, secret_key);
    if (ret != OK)
    {
        /* 10008 means key already applied succeeded */
        if (ret != 10008)
        {
            log_info(MSG_LOG_DBG, CRYPT, "apply secret key failed, ret:%ld.", ret);
            return ERROR;
        }
        else
        {
            if (strlen(secret_key) > 0)
                log_info(MSG_LOG_DBG, CRYPT, "secret key already applied(code:10008).");
            
            return KEY_EXIST_IN_SERVER;
        }
    }

    if (ret == OK)
    {    
        key_len = strlen(secret_key);
        if ( key_len < SECRET_KEY_LEN_MIN) 
        {
            log_info(MSG_LOG_DBG, CRYPT, 
                        "apply secret key failed, key len:%ld, expect larger than %ld.", 
                        key_len, SECRET_KEY_LEN_MIN);
            return ERROR;            
        }
    }
    
    log_info(MSG_LOG_DBG, CRYPT, "apply secret key OK, value:%s", secret_key);

    ret = IW_WriteKeycard(secret_key, NULL);
    log_info(MSG_LOG_DBG, CRYPT, "import secret key to sw-shield OK.");

    return OK;
}




/**
 * WARNing: generate pk and apply sk must be combined---depricated!
 * 1 generate pk
 * 2 apply sk and preserve
*/
#if DEBUG_FALSE
uint32_t init_sw_shield_ex(int8_t *dev_id, int8_t *pkey)
{
    int32_t ret;
    int8_t tmp_key[PUB_KEY_LEN_MAX] = {0};
    int8_t  secret_key[SECRET_KEY_LEN_MAX] = { 0 };   // device sk
    uint32_t key_len;


    if (!dev_id ||!*dev_id || strlen(dev_id)>DEV_ID_LEN_MAX)
    {
        log_info(MSG_LOG_DBG, CRYPT, "device id illegal.");
        return ERROR;
    }

    /* step1: gene temporary key-pair */
    ret = IW_InitDevice(dev_id, IWALL_SVKD_REPO);

    if (ret != OK)
        log_info(MSG_LOG_DBG, CRYPT, "init sw-shield failed ret = %d", ret);

    log_info(MSG_LOG_DBG, CRYPT, "init sw-shield OK");

    ret = IW_OpenDevice(dev_id, IWALL_SVKD_REPO);
    log_info(MSG_LOG_DBG, CRYPT, "open sw-shield ret = %#x", ret);

    /* step2: gene temporary key-pair */
    ret = IW_GenKeyRequest(dev_id, tmp_key);
    log_info(MSG_LOG_DBG, CRYPT, "dev %s\'s pk is %s", dev_id, tmp_key);
    
    strncpy(pkey, tmp_key, strlen(tmp_key));

    /* step3: apply secret key */
    ret = IW_Sendrequest(dev_id, pkey, secret_key);

    if (ret != OK)
    {
        /* 10008 means key already applied succeeded */
        if (ret != 10008)
        {
            log_info(MSG_LOG_DBG, CRYPT, "apply secret key failed, ret:%ld.", ret);
            return ERROR;
        }
        else
        {
            if (strlen(secret_key) > 0)
                log_info(MSG_LOG_DBG, CRYPT, "secret key already applied.");
        }
    }

    if (ret == OK)
    {    
        key_len = strlen(secret_key);
        if ( key_len < SECRET_KEY_LEN_MIN) 
        {
            log_info(MSG_LOG_DBG, CRYPT, 
                        "apply secret key failed, key len:%ld, expect larger than %ld.", 
                        key_len, SECRET_KEY_LEN_MIN);
            return ERROR;            
        }
    }
    
    log_info(MSG_LOG_DBG, CRYPT, "apply secret key OK, value:%s", secret_key);

    ret = IW_WriteKeycard(secret_key, NULL);
    log_info(MSG_LOG_DBG, CRYPT, "import secret key to sw-shield OK.");

    
    return ret;
}
#endif

/*
    out1:pub_matrix
    out2:skey_matrix
*/

#if 0

uint32_t gene_key_matrix(BYTE *pub_matrix, BYTE * skey_matrix)
{
    int32_t ret = OK;
    int32_t len, block_size;
    int32_t fd;
    BYTE*    pkmbuf;
    BYTE*    skmbuf;


    /* 1 p-key matrix */
    fd = open(SMT_PKM_FILE, O_RDONLY);
    if (fd < 0)
    {
        log_info(MSG_LOG_DBG, CRYPT, "pkm_open_err");
        return ERROR;
    }

    pkmbuf = (BYTE*)malloc(PUB_KEY_MATRIX_LEN_MAX);
    if (pkmbuf == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "malloc pkmbuf failed");
        return ERROR;
    }
    
    memset(pkmbuf, 0, PUB_KEY_MATRIX_LEN_MAX);

    // why subtract 256 ???
    block_size = PUB_KEY_MATRIX_LEN_MAX-256;
    len = read(fd, pkmbuf +256, block_size);
    if (len < block_size)
    {
        log_info(MSG_LOG_DBG, CRYPT, "read pkmbuf failed: len(%ld), need(%ld)", len, block_size);
        ret = ERROR;

        goto REL_RES;

    }
    
    memcpy(pub_matrix, pkmbuf, len);

    
    /* 2 s-key matrix */
    if (fd)
        close(fd);

    fd = open(SMT_SKM_FILE, O_RDONLY);
    if (fd < 0)
    {
        log_info(MSG_LOG_DBG, CRYPT, "skm_open_err!");
        ret = ERROR;

        goto REL_RES;
    }

    skmbuf = (BYTE*)malloc(SECRET_KEY_MATRIX_LEN_MAX);
    if (skmbuf == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "malloc skmbuf failed");
        ret = ERROR;

        goto REL_RES;
    }
    
    memset(skmbuf, 0, SECRET_KEY_MATRIX_LEN_MAX);
    
    block_size = SECRET_KEY_MATRIX_LEN_MAX-256;
    len = read(fd, skmbuf+256, block_size);
    if (len < block_size)
    {
        log_info(MSG_LOG_DBG, CRYPT, "read skmbuf failed: len(%ld), need(%ld)", len, block_size);
        return ERROR;
    }
    
    memcpy(skey_matrix, skmbuf, len);

REL_RES:    
    if (fd)
        close(fd);
    if (pkmbuf)
        free(pkmbuf);
    if (skmbuf)
        free(skmbuf);

    return ret;
}

#else


/**
*   CAUTION: beijing testX incorrect!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/
uint32_t gene_key_matrix(BYTE *pub_matrix, BYTE * skey_matrix)
{
    int32_t ret = OK;
    int32_t len, block_size, count;
    FILE     *fp = NULL;
    BYTE*    pkmbuf;
    BYTE*    skmbuf;


    /* 1 p-key matrix */
    fp = fopen(SMT_PKM_FILE, "rb");
    if (fp == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "pkm_open_err");
        return ERROR;
    }

    pkmbuf = (BYTE*)malloc(PUB_KEY_MATRIX_LEN_MAX);
    if (pkmbuf == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "malloc pkmbuf failed");
        return ERROR;
    }
    
    memset(pkmbuf, 0, PUB_KEY_MATRIX_LEN_MAX);

    // why subtract 256 ???
    block_size = PUB_KEY_MATRIX_LEN_MAX-256;
    count = 1;
    len = fread(pkmbuf + 256, block_size, count, fp);
    if (len < 0)
    {
        log_info(MSG_LOG_DBG, CRYPT, "read pkmbuf failed: len(%ld), need(%ld)", len, block_size*count);
        ret = ERROR;

        goto REL_RES;

    }

    memcpy(pub_matrix, pkmbuf, block_size);

    
    /* 2 s-key matrix */
    if (fp) {
        fclose(fp);
        fp = NULL;
    }

    fp = fopen(SMT_SKM_FILE, "rb");
    if (fp == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "skm_open_err!");
        ret = ERROR;

        goto REL_RES;
    }

    skmbuf = (BYTE*)malloc(SECRET_KEY_MATRIX_LEN_MAX);
    if (skmbuf == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "malloc skmbuf failed");
        ret = ERROR;

        goto REL_RES;
    }
    
    memset(skmbuf, 0, SECRET_KEY_MATRIX_LEN_MAX);
    
    block_size = SECRET_KEY_MATRIX_LEN_MAX-256;
    count = 1;
    len = fread(skmbuf + 256, block_size, count, fp);
    if (len < 0)
    {
        log_info(MSG_LOG_DBG, CRYPT, "read skmbuf failed: len(%ld), need(%ld)", len, block_size*count);
        return ERROR;
    }
    
    memcpy(skey_matrix, skmbuf, block_size);

REL_RES:    
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    if (pkmbuf)
    {
        free((char*)pkmbuf);
        pkmbuf = NULL;
    }
    if (skmbuf)
    {
        free((char*)skmbuf);
        pkmbuf = NULL;
    }

    return ret;
}


#endif

uint32_t sm2_encrypt_data(int8_t *devid, int8_t *orig_data,uint32_t orig_len, int8_t *ciph_data,uint32_t *ciph_len)
{
    int32_t ret;    
    proc_spec_data_t *priv;
    int8_t pub_key[PUB_KEY_LEN_MAX] = {0};

    get_proc_priv_data(&priv);
    ret = CPK_Get_IPK(devid, priv->pub_matrix, PUB_KEY_MATRIX_LEN_MAX, pub_key);
    log_info(MSG_LOG_DBG, MGT, "CPK_Get_IPK ret:%d", ret);
    log_info(MSG_LOG_DBG, MGT, "devid:%s", devid);
    
    ret = IW_SM2_EncryptData(pub_key, orig_data, strlen(orig_data)+1, ciph_data);
    log_info(MSG_LOG_DBG, MGT, "IW_SM2_EncryptData ret:%d", ret);
    *ciph_len = strlen(ciph_data);
    log_info(MSG_LOG_DBG, MGT, "sm2_encrypt_data cipher_len:%d, content as follow:", *ciph_len);
    PRINT_HEX(ciph_data, *ciph_len);
    
    return ret;
}

uint32_t sm4_encrypt_data(encrypt_data_t *algorithm, int8_t *orig_data,uint32_t orig_len, int8_t *ciph_data,uint32_t *ciph_len)
{
    int32_t ret;
    
    // stub:mode&padding
    ret = IW_SM4_ENCRYPT(SM4_MODE_ECB, SM4_NOPADDING, NULL, algorithm->key, 
                    orig_data, orig_len, ciph_data, ciph_len);
    log_info(MSG_LOG_DBG, MGT, "IW_SM4_ENCRYPT ret:%d", ret);
    log_info(MSG_LOG_DBG, MGT, "sm4_encrypt_data cipher_len:%d, content as follow:", *ciph_len);
    PRINT_HEX(ciph_data, *ciph_len);


    //stub----------------------------------------------------------------------------
    int8_t tmp_orig[CIPHER_DATA_LEN_MAX] = {0};
    int32_t tmp_val;
    ret = IW_SM4_DECRYPT(SM4_MODE_ECB, SM4_NOPADDING, NULL, algorithm->key, 
                        ciph_data, *ciph_len, tmp_orig, &tmp_val);
    log_info(MSG_LOG_DBG, MGT, "sm4_encrypt_data tmp_val:%d", tmp_val);
    log_info(MSG_LOG_DBG, MGT, "sm4_encrypt_data tmp_orig:%s", tmp_orig);


    return ret;
}


uint32_t encrypt_data(int8_t      *devid, int8_t *orig_data,uint32_t orig_len, int8_t *ciph_data,uint32_t *ciph_len)
{
    int32_t ret = INVALID_UINT32;
    dev_info_t devinfo = {0};
    encrypt_data_t *algo;
    
    get_devinfo_by_devid(devid, &devinfo);

    algo = &devinfo.crypt_type;
    
    log_info(MSG_LOG_DBG, CRYPT, "encrypt_data algorithm:%s(%d)",
                get_algorithm_str(algo->algorithm), algo->algorithm);

    switch (algo->algorithm)
    {
        case ALG_TYPE_NULL:
        {
            // set default algorithm here!
            break;
        }
        case ALG_TYPE_RSA:
        case ALG_TYPE_DES:
        case ALG_TYPE_DES3:
        case ALG_TYPE_AES:
        case ALG_TYPE_BASE64:
        case ALG_TYPE_SM3:
        {
            break;
        }
        case ALG_TYPE_SM2:
        {
            ret = sm2_encrypt_data(devid, orig_data, orig_len, ciph_data, ciph_len);
            break;
        }
        case ALG_TYPE_SM4:
        {
            // sm4 data len must be times of symmetric kesy
            orig_len = ((orig_len+SYMMETRIC_KEY_LEN-1)/SYMMETRIC_KEY_LEN)*SYMMETRIC_KEY_LEN;
            
            ret = sm4_encrypt_data(algo, orig_data, orig_len, ciph_data, ciph_len);
            break;
        }
        default:break;
    }

    log_info(MSG_LOG_DBG, CRYPT, "encrypt_data ret:%d", ret);

    return OK;
}


uint32_t sm2_decrypt_data(int8_t *ciph_data,uint32_t ciph_len, int8_t *orig_data,uint32_t *orig_len)
{
    return IW_SM2_DecryptData(ciph_data, ciph_len, orig_data, orig_len);
}

uint32_t sm4_decrypt_data(encrypt_data_t *algorithm, int8_t *ciph_data,uint32_t ciph_len, int8_t *orig_data,uint32_t *orig_len)
{
    int32_t ret;
    
    log_info(MSG_LOG_DBG, CRYPT, "sm4_decrypt_data algorithm->key:");
    PRINT_HEX(algorithm->key, strlen(algorithm->key));
    log_info(MSG_LOG_DBG, CRYPT, "ciph_data:");
    PRINT_HEX(ciph_data, ciph_len);

    // stub:mode&padding
    ret = IW_SM4_DECRYPT(SM4_MODE_ECB, SM4_NOPADDING, NULL, algorithm->key, 
                        ciph_data, ciph_len, orig_data, orig_len);

    return ret;
}

uint32_t decrypt_data(encrypt_data_t *algorithm, int8_t *ciph_data,uint32_t ciph_len, int8_t *orig_data,uint32_t *orig_len)
{
    int32_t ret;
    
    log_info(MSG_LOG_DBG, CRYPT, "decrypt_data algorithm:%s(%d)",
                get_algorithm_str(algorithm->algorithm), algorithm->algorithm);

    switch (algorithm->algorithm)
    {
        case ALG_TYPE_NULL:
        {
            // set default algorithm here!
            break;
        }
        case ALG_TYPE_RSA:
        case ALG_TYPE_DES:
        case ALG_TYPE_DES3:
        case ALG_TYPE_AES:
        case ALG_TYPE_BASE64:
        case ALG_TYPE_SM3:
        {
            break;
        }
        case ALG_TYPE_SM2:
        {
            ret = sm2_decrypt_data(ciph_data, ciph_len,orig_data, orig_len);
            break;
        }
        case ALG_TYPE_SM4:
        {
            ret = sm4_decrypt_data(algorithm, ciph_data, ciph_len, orig_data, orig_len);
            break;
        }
        default:break;
    }

    log_info(MSG_LOG_DBG, CRYPT, "decrypt_data ret:%d", ret);

    return OK;
}



// test API----->
void dbg_test_verify(char * devid, uint8_t *matrix, uint32_t klen)
{

    unsigned char testData[128] = { 0 };
    int32_t ret = OK;
    int32_t len, block_size, count;
    FILE     *fp = NULL;
    BYTE*    pkmbuf;
    BYTE*    skmbuf;
    uint8_t pub_matrix[PUB_KEY_MATRIX_LEN_MAX] = {0};     
    uint8_t skey_matrix[SECRET_KEY_MATRIX_LEN_MAX] = {0};


    /* 1 p-key matrix */
    fp = fopen(SMT_PKM_FILE, "rb");
    if (fp == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "pkm_open_err");
        return;
    }

    pkmbuf = (BYTE*)malloc(PUB_KEY_MATRIX_LEN_MAX);
    if (pkmbuf == NULL)
    {
        log_info(MSG_LOG_DBG, CRYPT, "malloc pkmbuf failed");
        return;
    }
    
    memset(pkmbuf, 0, PUB_KEY_MATRIX_LEN_MAX);

    // why subtract 256 ???
    block_size = PUB_KEY_MATRIX_LEN_MAX-256;
    count = 1;
    len = fread(pkmbuf + 256, block_size, count, fp);
    if (len < 0)
    {
        log_info(MSG_LOG_DBG, CRYPT, "read pkmbuf failed: len(%ld), need(%ld)", len, block_size*count);
        return;
    }

    memcpy(pub_matrix, pkmbuf, block_size);
    
    memset(testData, 0, strlen(testData));
    strcpy(testData, "chun hui dada, wanwu fusu. yangguang mingmei, wu gufu hao shiguang.");

    char pSignature[256] = { 0 };
    ret = IW_SignData(testData, strlen(testData), pSignature);
    printf("IW_SignData rv is %d\n", ret);

    char pSignaturefinal[512] = { 0 };
    ret = IW_ServerSignData(pSignature, pSignaturefinal);
    printf("IW_ServerSignData rv is %d\n", ret);
    printf("数字签名(rv = 0：成功) rv = %d\n被签名数据：%s\n签名值：%s\n", ret, testData, pSignaturefinal);


    //printf("proc_data->pub_matrix:%s\n", proc_data->pub_matrix);
    //dbg_print_char_in_buf(proc_data->pub_matrix, 128);
    //printf("pub_matrix:%s\n", pub_matrix);
    //dbg_print_char_in_buf(pub_matrix, PUB_KEY_MATRIX_LEN_MAX);
    //printf("pkmbuf:%s\n", pkmbuf);
    //dbg_print_char_in_buf(pkmbuf, PUB_KEY_MATRIX_LEN_MAX);

    ret = IW_VerifyData(matrix, klen, testData, strlen(testData), pSignaturefinal, devid);
    printf("\nSM2VerifySignData rv = %d\n", ret);
    printf("验证签名(rv = 0：成功) rv = %d\n\n", ret);
    return;
}


