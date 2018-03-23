/*
 * common.h
 *
 *  Created on: 2018-3-22
 *      Author: xuyang
 */

#include "common.h"
#include "crypt.h"



/* init sw-shield, return svr temp pk  

    IN1:dev_id
    OUT1:key
*/
uint32_t init_sw_shield(int8_t *dev_id, int8_t *pkey)
{
    int32_t ret;
    int8_t tmp_key[PUB_KEY_LEN_MAX] = {0};
    

    if (!dev_id ||!*dev_id || strlen(dev_id)>DEV_ID_LEN_MAX)
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "device id illegal.");
        return ERROR;
    }
    ret = IW_InitDevice(dev_id, "svkd/");

    if (ret != OK)
        PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "init sw-shield failed ret = %d", ret);

    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "init sw-shield OK");

    /* open dev */
    ret = IW_OpenDevice(dev_id, "svkd/");
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "open sw-shield ret = %#x", ret);

    /* gene temporary key-pair */
    ret = IW_GenKeyRequest(dev_id, tmp_key);
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "dev %s\'s pk is %s", dev_id, tmp_key);

    strncpy(pkey, tmp_key, strlen(tmp_key));

    return OK;
}


/*
    save secret key that recv from sk-center
    TE need execute /data/start_data.sh to generate data/libecm and ifport
        /data/libecm
        /data/start_data.sh
*/
uint32_t persist_secret_key(int8_t *dev_id, int8_t *pkey)
{
    int32_t ret;
    int8_t  secret_key[SECRET_KEY_LEN_MAX] = { 0 };   // device sk
    uint32_t key_len;
    
    // need open dev ? all disappointed
    //ret = IW_OpenDevice(dev_id, "svkd/");
    //PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "open sw-shield ret = %#x", ret);
    
    IW_Sendrequest(dev_id, pkey, secret_key);
    key_len = strlen(secret_key);
    
    if ( key_len < SECRET_KEY_LEN_MIN) 
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key failed, key len:%ld.", key_len);

        if (strlen(secret_key) > 0)
            PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key failed, return:%s.", secret_key);
        
        return ERROR;
    }
    
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key OK, value:%s", secret_key);

    ret = IW_WriteKeycard(secret_key, NULL);
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "import secret key to sw-shield OK.");

    return OK;
}


/**
 * WARNing: generate pk and apply sk must be combined
 * 1 generate pk
 * 2 apply sk and preserve
*/
void init_sw_shield_ex(int8_t *dev_id, int8_t *pkey)
{
    int32_t ret;
    int8_t tmp_key[PUB_KEY_LEN_MAX] = {0};
	int8_t  secret_key[SECRET_KEY_LEN_MAX] = { 0 };   // device sk
	uint32_t key_len;
    

    if (!dev_id ||!*dev_id || strlen(dev_id)>DEV_ID_LEN_MAX)
    {
	    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "device id illegal.");
        return;
    }
    
    /* step1: gene temporary key-pair */
	ret = IW_InitDevice(dev_id, "svkd/");

    if (ret != OK)
	    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "init sw-shield failed ret = %d", ret);
    
	PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "init sw-shield OK");

	ret = IW_OpenDevice(dev_id, "svkd/");
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "open sw-shield ret = %#x", ret);

    /* step2: gene temporary key-pair */
	ret = IW_GenKeyRequest(dev_id, tmp_key);
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "dev %s\'s pk is %s", dev_id, tmp_key);
    
    strncpy(pkey, tmp_key, strlen(tmp_key));

    /* step3: apply secret key */
    IW_Sendrequest(dev_id, pkey, secret_key);
    key_len = strlen(secret_key);
    
    if ( key_len < SECRET_KEY_LEN_MIN) 
    {
        PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key failed, key len:%ld.", key_len);

        if (strlen(secret_key) > 0)
            PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key failed, return:%s.", secret_key);
            
        return;
    }
    
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "apply secret key OK, value:%s", secret_key);

    ret = IW_WriteKeycard(secret_key, NULL);
    PRINT_SYS_MSG(MSG_LOG_DBG, CRYPT, "import secret key to sw-shield OK.");

    

}

void main6667(void)
{
	char testKeyId[16] = { 0 };
	printf("请输入一个标识用于申请密钥.(例如：id0001)\n");
	scanf("%s", testKeyId);
	if (testKeyId == NULL) {
		printf("您输入的标识为NULL");
		return;
	}
	printf("您输入的标识是\"%s\"", testKeyId);

	unsigned char testData[128] = { 0 };
	memset(testData, 0, strlen(testData));
	strcpy(testData, "this is test data! zhe shi ce shi shu ju.1234567890.");

	int rv = 0;
	char pBlob[256] = { 0 };
	char pEnvelopedKeyBlob[1024] = { 0 }; //设备私钥
	int		pubMatrixLen = 66560 + 256;//65 * 1024
	int		skeyMatrixLen = 1024 * 32 + 256;
	BYTE*	pkmbuf = (BYTE*)malloc(pubMatrixLen);
	BYTE*	skmbuf = (BYTE*)malloc(skeyMatrixLen);
	FILE	*fp = NULL;

	rv = IW_InitDevice(testKeyId, "svkd/");
	printf("初始化软盾设备(rv = 0：成功) rv = %d\n", rv);

	rv = IW_OpenDevice(testKeyId, "svkd/");
	printf("打开软盾设备(rv = 0：成功) rv = %d\n\n", rv);

	rv = IW_GenKeyRequest(testKeyId, pBlob);
	printf("生成临时密钥对(rv = 0：成功) rv = %d\n密钥对的公钥：%s\n", rv, pBlob);

    if (1)
        return;
#if 1

	fp = fopen("iwall/iwall.smt.pkm", "rb");
	//fp = fopen("../iwall.test.pkm", "rb");
	if (fp == NULL)
	{
		printf("pkm_open_err!\n");
		return;
	}
	//fread(pkmbuf, 1024 * 65 + 256, 1, fp);
	fread(pkmbuf + 256, 1024 * 65, 1, fp);
	if (fp) {
		fclose(fp);
		fp = NULL;
	}

	fp = fopen("iwall/iwall.smt.skm", "rb");
	//fp = fopen("../iwall.test.skm", "rb");
	if (fp == NULL)
	{
		printf("skm_open_err!\n");
		return;
	}
	//fread(skmbuf, 1024 * 32 + 256, 1, fp);
	fread(skmbuf + 256, 1024 * 32, 1, fp);
	if (fp) {
		fclose(fp);
		fp = NULL;
	}

	// pBlog -公钥
	// pEnvelopedKeyBlob -服务端返回的私钥
	//id和公钥发给密钥中心，密钥中心返回加密的私钥，用临时私钥解密后，存放在pEnvelopedKeyBlob
	IW_Sendrequest(testKeyId, pBlob, pEnvelopedKeyBlob);
	if (strlen(pEnvelopedKeyBlob) < 32) {
		printf("申请私钥失败：%s,请重新运行程序并尝试用新的标识来申请私钥\n", pEnvelopedKeyBlob);
		return;
	}
	else {
		printf("申请私钥成功：Socket返回的私钥保护结构为 %s\n", pEnvelopedKeyBlob);
	}

	char seServerKey[256] = { 0 };
	//rv = IW_WriteKeycard(pEnvelopedKeyBlob,seServerKey);
	rv = IW_WriteKeycard(pEnvelopedKeyBlob, NULL);
	printf("导入私钥到软盾(rv = 0：成功) rv = %d\n", rv);

// 通过id计算对端公钥pPublic
	char pPublic[512] = { 0 };
	rv = CPK_Get_IPK(testKeyId, pkmbuf, pubMatrixLen, pPublic);
	//printf("\nCPK_Get_IPK rv = %d\npPublic is: %s", rv, pPublic);
	printf("计算公钥(rv = 0：成功) rv = %d\n标识(%s)的公钥：%s\n\n", rv, testKeyId, pPublic);

// TE
	char pSignature[256] = { 0 };
	rv = IW_SignData(testData, strlen(testData), pSignature);
	//printf("IW_SignData rv is %d\n", rv);

// svr
	char pSignaturefinal[512] = { 0 };
	rv = IW_ServerSignData(pSignature, pSignaturefinal);
	//printf("IW_ServerSignData rv is %d\n", rv);
	printf("数字签名(rv = 0：成功) rv = %d\n被签名数据：%s\n签名值：%s\n", rv, testData, pSignaturefinal);

// TE
	rv = IW_VerifyData(pkmbuf, pubMatrixLen, testData, strlen(testData), pSignaturefinal, testKeyId);
	//printf("\nSM2VerifySignData rv = %d\n", rv);
	printf("验证签名(rv = 0：成功) rv = %d\n\n", rv);


// 随机数？
	rv = WriteToken(1, "12243432432423");
	//printf("\nWriteToken rv = %d\n", rv);

	char token[64] = { 0 };
	rv = ReadToken(1, token);
	//printf("\nReadToken rv = %d\ntoken is %s\n", rv,token);

	char cipher[1024] = { 0 };
	rv = IW_SM2_EncryptData(pPublic, testData, strlen(testData), cipher);
	printf("SM2 加密(rv = 0：成功) rv = %d\n待加密的数据：%s\n加密后的密文：%s\n", rv, testData, cipher);
	//printf("\nIW_SM2_EncryptData rv = %d\n,%s", rv, cipher);

	int	 pdataLen = 512;
	char pdata[512] = { 0 };
	//memset(cipher, 0, strlen(cipher));
	//strcpy(cipher, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8RFjYRDtchtW5+I97DaEhXIudtzPYggSy5RjuwrOSjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy8lAsr4ca8WWAx0xRwBLZsP8Dy3hZPOxCDpS712AsqriAQlg/IK8N/cYiXn8ITI9mJNOdTheDfta+pInsHO3LTIAAAADWdh0BePQQCezWL50T+cJGDxwEgXdpB/+nmPTjZKj8XMukoW3kIowGbGHQFmyYiYItwA=pkdfCryjH+mBWbd4C19NAXXOTlBxYIbTZ0uUSzw=");
	rv = IW_SM2_DecryptData(cipher, strlen(cipher), pdata, &pdataLen);
	printf("SM2 解密(rv = 0：成功) rv = %d\n待解密的数据：%s\n解密后的明文：%s\n\n", rv, cipher, pdata);
	//printf("\nIW_SM2_DecryptData rv = %d, plain = %s\n", rv, pdata);

	BYTE skey[128] = { 0 };
	memset(cipher, 0, 1024);
	rv = IW_SM2_MakeEnv(pkmbuf, pubMatrixLen, testKeyId, testData, strlen(testData), cipher);
	printf("制作数字信封(rv = 0：成功) rv = %d\n信封中的数据：%s\n数字信封：%s\n", rv, testData, cipher);
	//printf("\nIW_SM2_MakeEnv rv = %d,%s\n", rv, cipher);

	int skeyLen = 128;
	memset(skey, 0, 128);
	//memset(cipher, 0, strlen(cipher));
	//strcpy(cipher, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8RFjYRDtchtW5+I97DaEhXIudtzPYggSy5RjuwrOSjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAy8lAsr4ca8WWAx0xRwBLZsP8Dy3hZPOxCDpS712AsqriAQlg/IK8N/cYiXn8ITI9mJNOdTheDfta+pInsHO3LTIAAAADWdh0BePQQCezWL50T+cJGDxwEgXdpB/+nmPTjZKj8XMukoW3kIowGbGHQFmyYiYItwA=pkdfCryjH+mBWbd4C19NAXXOTlBxYIbTZ0uUSzw=");
	rv = IW_SM2_OpenEnv(cipher, skey, &skeyLen);
	printf("打开数字信封(rv = 0：成功) rv = %d\n数字信封：%s\n信封中的数据：%s\n\n", rv, cipher, skey);
	//printf("\nIW_SM2_OpenEnv rv = %d, plain(ex) = %s\n", rv, skey);

	int keyIdLen = 128;
	char keyId[128] = { 0 };
	rv = IW_ReadKeyID(keyId, &keyIdLen);
	printf("读取软盾设备的标识(rv = 0：成功) rv = %d\n软盾标识：%s\n", rv, keyId);
	//printf("\nReadKeyID rv = %d keyId = %s\n", rv, keyId);


#endif

	//CloseLogFile();
	printf("测试完成\n");


	if (pkmbuf)
		free(pkmbuf);
	if (skmbuf)
		free(skmbuf);

	//system("pause");
}

void main_crypt()
{
	int i = 0;
	for (i; i < 1; i++)
	{
		main6667();
	}
	//system("pause");
}
