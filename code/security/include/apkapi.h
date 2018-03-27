#ifndef __CPK_APK_API_H__
#define __CPK_APK_API_H__
//#include "skfapi.h"

#define APK_DLL_EXPORTS 1

#ifdef APK_DLL_EXPORTS
#define APK_DLL_API __attribute__((visibility("default")))
#endif

#define SM4_MODE_ECB    1
#define SM4_MODE_CBC    0
#define SM4_PKCSPADDING 1
#define SM4_NOPADDING   0

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef BYTE
    typedef unsigned char  BYTE;
#endif

	/*
	*	初始化设备
	*	szUserInfo			[IN] 用户输入的设备信息、机器指纹、PIN码或其它标识信息，可以为空
	*	svkdPath			[IN] SVKD文件存放路径
	*	绑定完成后，IW_OpenDevice函数必须传入相同的值
	*/
	APK_DLL_API int IW_InitDevice(char *szUserInfo, char* svkdPath);

	/*
	*	打开设备
	*	szUserInfo			[IN] 用户输入的设备信息、机器指纹、PIN码或其它标识信息，可以为空
	*	svkdPath			[IN] SVKD文件存放路径，必须与初始化设备的路径相同
	*/
	APK_DLL_API int IW_OpenDevice(char *szUserInfo, char* svkdPath);

	/*
	*	请求CPK密钥对, 产生临时公私钥对，并吐出公钥用于CPK私钥的加密秘钥
	*	szUserId			[IN]  用户的身份标识ID
	*	pBlob				[OUT] pBlob为ECCPUBLICKEYBLOB 做base64以后的结果
	*/
	APK_DLL_API int IW_GenKeyRequest(char *szUserId, char *pBlob);

	/*
	*	写入密钥对
	*	pEnvelopedKeyBlob	[IN]  导入密钥对（PENVELOPEDKEYBLOB结构base64值）
	*	seServerKey			[OUT] 分散密钥服务器部分
	*	seServerKey为NULL时，不输出服务器分散部分，全部密钥分散保存在本地
	*/
	APK_DLL_API int IW_WriteKeycard(char *pEnvelopedKeyBlob, char *seServerKey);

	/*
	*	读取VKD中的KeyID，调用此函数前需打开设备
	*	szUserId		    [OUT] 用户的身份标识ID
	*	返回0成功，并返回正确的ID，否则返回非零
	*/
	APK_DLL_API int IW_ReadKeyID(char *szUserId, int *userIDLen);

	/*
	*	计算公钥,输出base64后公钥国密结构。
	*	userId				[IN]  用户标识
	*	pubMatrixData		[IN]  公钥矩阵数据流
	*	pubMatrixLen		[IN]  公钥矩阵数据长度
	*	pPublic				[OUT] 返回SM2公钥数据结构
	*/
	APK_DLL_API int CPK_Get_IPK(char *userId, BYTE *pbPubMitrixData, int nPubMitrixDataLen, char *pPublic);

	/*
	*	数据签名
	*	pbData				[IN]  待签名数据，内部先做SM3摘要，然后对摘要进行签名
	*	ulDataLen			[IN]  待签名数据长度
	*	ulDataLen			[OUT] 传出签名值（base64后的值）
	*/
	APK_DLL_API int IW_SignData(BYTE *pbData, int ulDataLen, char *pSignature);

	/*
	*	服务端数据签名
	*	pbData		        [IN]  客户端签名后的数据（base64后的值）
	*	pSignature	        [OUT] 最终签名值（base64后的值）
	*	使用此函数前必须从IW_SignData（）获得第一次签名信息
	*/
	APK_DLL_API int IW_ServerSignData(char *pbData, char *pSignature);

	/*
	*	数据验签
	*	pubMatrixData		[IN] 公钥矩阵数据流
	*	pubMatrixLen		[IN] 公钥矩阵数据长度
	*	pbData				[IN] 被签名数据,base64后结果
	*	ulDataLen			[IN] 被签名数据长度
	*	pSignature			[IN] 签名数据 base64后结果
	*	usrID				[IN] 用户ID
	*/
	APK_DLL_API int IW_VerifyData(BYTE *pubMatrixData, int pubMatrixLen, BYTE *pbData, int ulDataLen, char *pSignature, char *usrID);

	/*
	*	数据加密
	*	pPublic		        [IN]  加密公钥，ECCPUBLICKEYBLOB结构体base64以后的数据
	*	pbData 		        [IN]  待加密数据
	*	ulDataLen	        [IN]  待加密数据长度
	*	pCipher		        [OUT] 传出加密后的值（base64后的值）
	*/
	APK_DLL_API int IW_SM2_EncryptData(char * pPublic, BYTE *pbData, int ulDataLen, char *pCipher);
    
	/*
	*	数据解密
	*	pCipher		        [IN]  加密后的密文（base64后的值）
	*	ulCipherDataLen     [IN]  加密后密文长度
	*	pbData 		        [OUT] 解密后的明文
	*	ulDataLen	        [OUT] 解密后的明文长度
	*/
	APK_DLL_API int IW_SM2_DecryptData(char*pCipher, int ulCipherDataLen, BYTE *pData, int* ulPlainDataLen);

    /*
     *    数据加密
     *    pPublic           [IN]  加密公钥，ECCPUBLICKEYBLOB结构体base64以后的数据
     *    pbData            [IN]  待加密数据
     *    ulDataLen         [IN]  待加密数据长度
     *    pCipher           [OUT] 传出加密后的值（base64后的值）
     */
	APK_DLL_API int IW_SM2_EncryptDataEx(char * pPublic, BYTE *pbData, int ulDataLen, char *pCipher);
    
    /*
     *    数据解密
     *    pCipher           [IN]  加密后的密文（base64后的值）
     *    ulCipherDataLen   [IN]  加密后密文长度
     *    pbData            [OUT] 解密后的明文
     *    ulDataLen         [OUT] 解密后的明文长度
     */
	APK_DLL_API int IW_SM2_DecryptDataEx(char *pCipher, int ulCipherDataLen, BYTE *pData, int* ulPlainDataLen);

    /*
     *    制作信封
     *    pubMatrixData     [IN]  公钥矩阵数据
     *    pubMatrixLen      [IN]  公钥矩阵数据长度
     *    addresseeId       [IN]  用户标识
     *    skey              [IN]  信封原文
     *    skeyLen           [IN]  信封原文长度
     *    env               [OUT] 信封值
     */
	APK_DLL_API int IW_SM2_MakeEnv(BYTE *pubMatrixData, int pubMatrixLen, const char *addresseeId,
                       const BYTE *skey, int skeyLen, char *env);

    /*
     *    打开信封
     *    env               [IN]  信封值
     *    skey              [OUT] 信封原文
     *    skeyLen           [OUT] 信封原文长度
     */
	APK_DLL_API int IW_SM2_OpenEnv(char *env, BYTE *skey, int *skeyLen);

    /*
     *    SM3摘要
     *    data              [IN]  摘要原文
     *    dataLen           [IN]  摘要原文数据长度
     *    digest            [OUT] 摘要值
     *    digestLen         [OUT] 摘要值长度
     */
    APK_DLL_API int IW_SM3_DIGEST(unsigned char *data, unsigned int dataLen, unsigned char *digest, unsigned int *digestLen);
    
    /*
     *    SM4加密
     *    mode              [IN]  ECB / CBC 模式 （SM4_MODE_ECB/SM4_MODE_CBC）
     *    padding           [IN]  是否进行padding （SM4_PKCSPADDING / SM4_NOPADDING）
     *    iv                [IN]  CBC模式需要填入偏移量
     *    key               [IN]  对称加密的密钥
     *    input             [IN]  加密的原文数据
     *    inputLen          [IN]  输入加密原文数据的长度
     *    output            [OUT] 加密后的数据
     *    uloutputLen       [OUT] 加密后的数据长度
     */
    APK_DLL_API int IW_SM4_ENCRYPT(int mode, int padding, unsigned char *iv, unsigned char *key, unsigned char *input,
                       int inputLen, unsigned char *output, int *uloutputLen);
    /*
     *    SM4解密
     *    mode              [IN]  ECB / CBC 模式 （SM4_MODE_ECB/SM4_MODE_CBC）
     *    padding           [IN]  是否进行padding （SM4_PKCSPADDING / SM4_NOPADDING）
     *    iv                [IN]  CBC模式需要填入偏移量
     *    key               [IN]  对称加密的密钥
     *    input             [IN]  密文数据
     *    inputLen          [IN]  密文数据的长度
     *    output            [OUT] 解密后的数据
     *    uloutputLen       [OUT] 解密后的数据长度
     */
    APK_DLL_API int IW_SM4_DECRYPT(int mode, int padding, unsigned char *iv, unsigned char *key, unsigned char *input,
                       int inputLen, unsigned char *output, int *uloutputLen);

    /*
     *    获取私钥
     *    pbISK             [OUT] 私钥
     */
	APK_DLL_API int CPK_Get_ISK(unsigned char*pbISK);

    /*
     *    获取随机数
     *    randData          [OUT] 随机数
     *    randLen           [IN]  要获取的随机数长度
     */
	APK_DLL_API int IW_GetRandom(unsigned char *randData, int randLen);

    /*
     *    Base64 编码
     *    clear             [IN]  需要编码的数据
     *    clearLen          [IN]  编码数据的长度
     *    base64            [OUT] 编码数据
     *    base64Len         [OUT] 编码数据长度
     *    maxLineLen        [IN]  每行最大数据长度
     */
	APK_DLL_API int Base64Encode(const BYTE* clear, int clearLen, char* base64, int* base64Len, int maxLineLen);

    /*
     *    Base64 解码
     *    base64            [IN]  编码数据
     *    base64Len         [IN]  编码数据的长度
     *    clear             [OUT] 解码数据
     *    clearLen          [OUT] 解码数据长度
     */
	APK_DLL_API int Base64Decode(const char* base64, int base64Len, BYTE* clear, int* clearLen);

	/*
	*	写入Token或其他数据到SVKD中
	*	num					[IN] Token序列号，可选1、2、3
	*	token				[IN] Token值，小于80字节
	*/
	APK_DLL_API int WriteToken(int num, char *token);

	/*
	*	从SVKD中读取Token
	*	num					[IN] Token序列号，可选1、2、3、4
	*	token				[OUT] Token值,需要初始化好内存空间
	*/
	APK_DLL_API int ReadToken(int num, char *token);

	/**********************************************************************************/
	//  扩展接口
	//  唯传 >> 校验数据包
	//APK_DLL_API int Ext_PacketCheck(unsigned char *pbPubMatrixData, int nPubMatrixDataLen, unsigned char *packet);
#ifdef  __cplusplus
}
#endif

#endif

