#ifndef __CPK_APK_API_H__
#define __CPK_APK_API_H__
//#include "skfapi.h"

#define APK_DLL_EXPORTS 1


#ifdef APK_DLL_EXPORTS
#define APK_DLL_API __attribute__((visibility("default")))
#endif

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
	*	szUserId			[IN] 用户的身份标识ID
	*	pBlob				[OUT] pBlob为ECCPUBLICKEYBLOB 做base64以后的结果
	*/
	APK_DLL_API int IW_GenKeyRequest(char *szUserId, char *pBlob);

	/*
	*	写入密钥对
	*	pEnvelopedKeyBlob	[IN] 导入密钥对（PENVELOPEDKEYBLOB结构base64值）
	*	seServerKey			[OUT]分散密钥服务器部分
	*	seServerKey为NULL时，不输出服务器分散部分，全部密钥分散保存在本地
	*/
	APK_DLL_API int IW_WriteKeycard(char *pEnvelopedKeyBlob, char *seServerKey);

	/*
	*	读取VKD中的KeyID，调用此函数前需打开设备
	*	szUserId		[OUT] 用户的身份标识ID
	*	返回0成功，并返回正确的ID，否则返回非零
	*/
	APK_DLL_API int IW_ReadKeyID(char *szUserId, int *userIDLen);

	/*
	*	数据签名
	*	pbData				[IN] 待签名数据，内部先做SM3摘要，然后对摘要进行签名
	*	ulDataLen			[IN] 待签名数据长度
	*	ulDataLen			[OUT]传出签名值（base64后的值）
	*/
	APK_DLL_API int IW_SignData(BYTE *pbData, int ulDataLen, char *pSignature);

	/*
	*	服务端数据签名
	*	pbData		 [IN] 客户端签名后的数据（base64后的值）
	*	pSignature	 [OUT]最终签名值（base64后的值）
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
	*	pPublic		 [IN] 加密公钥，ECCPUBLICKEYBLOB结构体base64以后的数据
	*	pbData 		 [IN] 待加密数据
	*	ulDataLen	 [IN] 待加密数据长度
	*	pCipher		 [OUT]传出加密后的值（base64后的值）
	*/
	APK_DLL_API int IW_SM2_EncryptData(char * pPublic, BYTE *pbData, int ulDataLen, char *pCipher);
    
	/*
	*	数据解密
	*	pCipher		 [IN]  加密后的密文（base64后的值）
	*	ulCipherDataLen [IN] 加密后密文长度
	*	pbData 		 [OUT] 解密后的明文
	*	ulDataLen	 [OUT] 解密后的明文长度
	*/
	APK_DLL_API int IW_SM2_DecryptData(char*pCipher, int ulCipherDataLen, BYTE *pData, int* ulPlainDataLen);

	/*
	*    数据加密
	*    pPublic         [IN] 加密公钥，ECCPUBLICKEYBLOB结构体base64以后的数据
	*    pbData          [IN] 待加密数据
	*    ulDataLen 	  [IN] 待加密数据长度
	*    pCipher         [OUT]传出加密后的值（base64后的值）
	*/
	APK_DLL_API int IW_SM2_EncryptDataEx(char * pPublic, BYTE *pbData, int ulDataLen, char *pCipher);
    
	/*
	*    数据解密
	*    pCipher         [IN]  加密后的密文（base64后的值）
	*    ulCipherDataLen [IN] 加密后密文长度
	*    pbData          [OUT] 解密后的明文
	*    ulDataLen       [OUT] 解密后的明文长度
	*/
	APK_DLL_API int IW_SM2_DecryptDataEx(char *pCipher, int ulCipherDataLen, BYTE *pData, int* ulPlainDataLen);

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

	/*
	*	计算公钥,输出base64后公钥国密结构。
	*	userId				[IN] 用户标识
	*	pubMatrixData		[IN] 公钥矩阵数据流
	*	pubMatrixLen		[IN] 公钥矩阵数据长度
	*	pPublic				[OUT] 返回SM2公钥数据结构
	*/
	APK_DLL_API int CPK_Get_IPK(char *userId, BYTE *pbPubMitrixData, int nPubMitrixDataLen, char *pPublic);

	/**********************************************************************************/
	/* Function:
	*   int IW_SM2_MakeEnv(const char *pubmatrix, const char *addresseeId,
	*                         const unsigned char *skey, int skeyLen, unsigned char *env,
	*                         int *envLen)
	* Purpose:
	*   Make digital envelope
	*
	* Parameters:
	*   pubMatrixData
	*       [in] public matrix data
	*	pubMatrixLen
	*		[in] the length of public matrix data
	*   addresseeId
	*       [in] the identity of addressee
	*   skey
	*       [in] session key
	*   skeyLen
	*       [in] the length of session key
	*   env
	*       [out] digital envelope
	* Return Values:
	*   If the function succeeds, the return value is zero.
	*   If the function fails, the return value is error code. */
	/**********************************************************************************/
	APK_DLL_API int IW_SM2_MakeEnv(BYTE *pubMatrixData, int pubMatrixLen, const char *addresseeId,
		const BYTE *skey, int skeyLen, char *env);

	/**********************************************************************************/
	/* Function:
	*   int IW_SM2_OpenEnv(int isExport, unsigned char keyIndex, unsigned char *env,
	*                  int envLen, unsigned char *skey, int *skeyLen)
	*
	* Purpose:
	*   Open digital envelope
	*
	* Parameters:
	*   env
	*       [in] digital envelope (from chip)
	*   skey
	*       [out] session key
	*   skeyLen
	*       [in] specifies the maximum size of the buffer
	*       [out] the length of session key
	*
	* Return Values:
	*   If the function succeeds, the return value is zero.
	*   If the function fails, the return value is error code. */
	/**********************************************************************************/
	APK_DLL_API int IW_SM2_OpenEnv(char *env, BYTE *skey, int *skeyLen);
	/**********************************************************************************/
	/* Function:
	*   int Base64Encode(const unsigned char* clear, int clearLen, char* base64, 
	*                    int* base64Len, int maxLineLen)
	*
	* Purpose:
	*   Base64 encode
	*
	* Parameters:
	*   clear
	*       [in] clear text
	*   clearLen
	*       [in] the length of clear text
	*   base64
	*       [out] base64 string
	*   base64Len
	*       [in] specifies the maximum size of the buffer
	*       [out] the length of base64 string
	*   maxLineLen
	*       [in] max length of a line
	*
	* Return Values:
	*   If the function succeeds, the return value is zero.
	*   If the function fails, the return value is error code. */
	/**********************************************************************************/
	APK_DLL_API int Base64Encode(const BYTE* clear, int clearLen, char* base64,
		int* base64Len, int maxLineLen);

	/**********************************************************************************/
	/* Function:
	*   int Base64Decode(const char* base64, int base64Len, unsigned char* clear, int *clearLen)
	*
	* Purpose:
	*   Base64 decode
	*
	* Parameters:
	*   base64
	*       [in] base64 string
	*   base64len
	*       [in] lthe length of base64 string
	*   clear
	*       [out] clear text
	*   clearLen
	*       [in] specifies the maximum size of the buffer
	*       [out] the length of clear text
	*
	* Return Values:
	*   If the function succeeds, the return value is zero.
	*   If the function fails, the return value is error code. */
	/**********************************************************************************/
	APK_DLL_API int Base64Decode(const char* base64, int base64Len, BYTE* clear, int* clearLen);
    
//    void test_random();

#ifdef  __cplusplus
}
#endif

#endif	

