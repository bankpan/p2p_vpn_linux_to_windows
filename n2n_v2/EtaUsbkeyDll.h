#ifndef EtaUsbkeyDll_H

#define EtaUsbkeyDll_H 1

#ifdef __cplusplus
extern "C" {
#endif


#ifdef _WIN32

#ifdef ETAUSBKEYDLL_EXPORTS
#define ETAUSBKEY_API __declspec(dllexport)
#else
#define ETAUSBKEY_API __declspec(dllimport)
#endif

#else

#define ETAUSBKEY_API

#endif

/*
** sUserPin : usbkey用户口令
** nCount:    返回查询到的密钥文件个数
** sLabel:    要查询的密钥文件名称，当名称为空时，查询usbkey中全部的密钥文件
** return: 0  
*/
ETAUSBKEY_API int CheckDataKey( char *sUserPin, int *nCount, char *sLabel );

/*
** sUserPin : usbkey用户口令
** sLabel:    要删除的密钥文件名称，当名称为空时，删除usbkey中全部的密钥文件
** return: 0  
*/
ETAUSBKEY_API int DeleteDataKey( char *sUserPin, char *sLabel );

/*
** sUserPin : usbkey用户口令
** nOutput:   返回解包后的密钥文件
** nLen：     输入缓冲区长度，返回解包后的数据流长度
** sLabel:    要解包的密钥文件名称，名称不能为空
** return: 0  
*/
ETAUSBKEY_API int UnWrapDataKey( char *sUserPin, char *sOutput, int *nLen, char *sLabel );

/*
** sUserPin : usbkey用户口令
** nData:     输入要打包的数据流
** nLen：     输入缓冲区长度
** sLabel:    要打包的密钥文件名称，名称不能为空
**
** 说明：     可以创建的密钥文件个数最多为50个，单个密钥文件最大是60K字节，usbkey可以存储的总容量是75K字节。
** return: 0  
*/
ETAUSBKEY_API int WrapDataKey(char *sUserPin, char *sData, int nLen, char *sLabel);

/*
** nSerial:   返回查询到的序列号，一般为16个字节
** sLen:      输入缓冲区长度，一般为17个字节，不能小于17个字节
** return: 0  
*/
ETAUSBKEY_API int GetUsbKeySerial(char *sSerial, int nLen);

/*
** sUserPin : usbkey用户口令
**
** 说明：检查是否为合法的KEY
** return: 0  
*/
ETAUSBKEY_API int CheckEtaUsbKey( char *sUserPin );

/*
** pSlot : 接收检测到的USBKEY 槽位置
**           该接口为阻塞模式，等待事件发生才返回。
**          当pSlot 不为空时，检测到USBKEY 接口返回
**          当pSlot 为NULL 时，检测到USBKEY 移除接口返回
**
** 说明：检测设备USB接口是否有KEY 连接
** return:   
*/
ETAUSBKEY_API void CheckAndWaitEvent( unsigned long *pSlot );

/*
**          该接口为非阻塞模式
**          检测到USBKEY 接口返回1，否则返回0
**
** 说明：检测设备USB接口是否有KEY 连接
** return: 0   
*/
ETAUSBKEY_API int CheckPullEvent( void );

/*
** sUserPin : usbkey用户口令
** sOutput  : 返回证书缓冲区，缓冲区长度一般默认设置为4096 字节
** nLen      : 缓冲区大小，一般默认设置为4096，返回实际获取的字节数
**               这里的nLen 需大于实际获取的字节数，否则函数返回错误
**
** 说明：读取X509 证书，输出为X509 证书格式，直接用函数d2i_X509 获取证书
** return:  0 
*/
ETAUSBKEY_API int GetCertValue_X509( char *sUserPin, char *sOutput, int *nLen );

/*
** sUserPin : usbkey用户口令
** SignData  : 签名数据
** SignDataLen      : 签名数据长度
** signature  : 返回签名值
** signatureLen      : 返回签名长度
** 说明: 获取RSA签名，成功返回0 和对应的签名长度
** return:  0 
*/
ETAUSBKEY_API int GetRsaSign( char *sUserPin, char *SignData, int SignDataLen , char *signature, int *signatureLen );

/*
** Cert : DER 编码的证书
** SignData  : 签名数据
** SignDataLen      : 签名数据长度
** signature  : 签名值
** signatureLen      : 签名值长度
** 说明: 校验RSA签名，成功返回0 ，失败返回非0 值
** return:  0 
*/
ETAUSBKEY_API int GetRsaVerify( char *Cert, int CertLen, char *SignData, int SignDataLen , char *signature, int signatureLen );

#ifdef LINUX

/*
** CertData  : 证书数据
** CaFilePath  : 根证书文件名 (包含路径)
** 说明: 校验证书有效性，成功返回0 ，失败返回非0 值
** return:  0 
*/
ETAUSBKEY_API int VerifyCertificate( char *CertData, char *CaFilePath );

#endif

ETAUSBKEY_API int ImportP12ToUsbkey (char *sUserPin, char *sP12File, char *strPwd);

#ifdef __cplusplus
};
#endif

#endif

