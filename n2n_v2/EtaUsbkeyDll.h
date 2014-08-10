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
** sUserPin : usbkey�û�����
** nCount:    ���ز�ѯ������Կ�ļ�����
** sLabel:    Ҫ��ѯ����Կ�ļ����ƣ�������Ϊ��ʱ����ѯusbkey��ȫ������Կ�ļ�
** return: 0  
*/
ETAUSBKEY_API int CheckDataKey( char *sUserPin, int *nCount, char *sLabel );

/*
** sUserPin : usbkey�û�����
** sLabel:    Ҫɾ������Կ�ļ����ƣ�������Ϊ��ʱ��ɾ��usbkey��ȫ������Կ�ļ�
** return: 0  
*/
ETAUSBKEY_API int DeleteDataKey( char *sUserPin, char *sLabel );

/*
** sUserPin : usbkey�û�����
** nOutput:   ���ؽ�������Կ�ļ�
** nLen��     ���뻺�������ȣ����ؽ���������������
** sLabel:    Ҫ�������Կ�ļ����ƣ����Ʋ���Ϊ��
** return: 0  
*/
ETAUSBKEY_API int UnWrapDataKey( char *sUserPin, char *sOutput, int *nLen, char *sLabel );

/*
** sUserPin : usbkey�û�����
** nData:     ����Ҫ�����������
** nLen��     ���뻺��������
** sLabel:    Ҫ�������Կ�ļ����ƣ����Ʋ���Ϊ��
**
** ˵����     ���Դ�������Կ�ļ��������Ϊ50����������Կ�ļ������60K�ֽڣ�usbkey���Դ洢����������75K�ֽڡ�
** return: 0  
*/
ETAUSBKEY_API int WrapDataKey(char *sUserPin, char *sData, int nLen, char *sLabel);

/*
** nSerial:   ���ز�ѯ�������кţ�һ��Ϊ16���ֽ�
** sLen:      ���뻺�������ȣ�һ��Ϊ17���ֽڣ�����С��17���ֽ�
** return: 0  
*/
ETAUSBKEY_API int GetUsbKeySerial(char *sSerial, int nLen);

/*
** sUserPin : usbkey�û�����
**
** ˵��������Ƿ�Ϊ�Ϸ���KEY
** return: 0  
*/
ETAUSBKEY_API int CheckEtaUsbKey( char *sUserPin );

/*
** pSlot : ���ռ�⵽��USBKEY ��λ��
**           �ýӿ�Ϊ����ģʽ���ȴ��¼������ŷ��ء�
**          ��pSlot ��Ϊ��ʱ����⵽USBKEY �ӿڷ���
**          ��pSlot ΪNULL ʱ����⵽USBKEY �Ƴ��ӿڷ���
**
** ˵��������豸USB�ӿ��Ƿ���KEY ����
** return:   
*/
ETAUSBKEY_API void CheckAndWaitEvent( unsigned long *pSlot );

/*
**          �ýӿ�Ϊ������ģʽ
**          ��⵽USBKEY �ӿڷ���1�����򷵻�0
**
** ˵��������豸USB�ӿ��Ƿ���KEY ����
** return: 0   
*/
ETAUSBKEY_API int CheckPullEvent( void );

/*
** sUserPin : usbkey�û�����
** sOutput  : ����֤�黺����������������һ��Ĭ������Ϊ4096 �ֽ�
** nLen      : ��������С��һ��Ĭ������Ϊ4096������ʵ�ʻ�ȡ���ֽ���
**               �����nLen �����ʵ�ʻ�ȡ���ֽ��������������ش���
**
** ˵������ȡX509 ֤�飬���ΪX509 ֤���ʽ��ֱ���ú���d2i_X509 ��ȡ֤��
** return:  0 
*/
ETAUSBKEY_API int GetCertValue_X509( char *sUserPin, char *sOutput, int *nLen );

/*
** sUserPin : usbkey�û�����
** SignData  : ǩ������
** SignDataLen      : ǩ�����ݳ���
** signature  : ����ǩ��ֵ
** signatureLen      : ����ǩ������
** ˵��: ��ȡRSAǩ�����ɹ�����0 �Ͷ�Ӧ��ǩ������
** return:  0 
*/
ETAUSBKEY_API int GetRsaSign( char *sUserPin, char *SignData, int SignDataLen , char *signature, int *signatureLen );

/*
** Cert : DER �����֤��
** SignData  : ǩ������
** SignDataLen      : ǩ�����ݳ���
** signature  : ǩ��ֵ
** signatureLen      : ǩ��ֵ����
** ˵��: У��RSAǩ�����ɹ�����0 ��ʧ�ܷ��ط�0 ֵ
** return:  0 
*/
ETAUSBKEY_API int GetRsaVerify( char *Cert, int CertLen, char *SignData, int SignDataLen , char *signature, int signatureLen );

#ifdef LINUX

/*
** CertData  : ֤������
** CaFilePath  : ��֤���ļ��� (����·��)
** ˵��: У��֤����Ч�ԣ��ɹ�����0 ��ʧ�ܷ��ط�0 ֵ
** return:  0 
*/
ETAUSBKEY_API int VerifyCertificate( char *CertData, char *CaFilePath );

#endif

ETAUSBKEY_API int ImportP12ToUsbkey (char *sUserPin, char *sP12File, char *strPwd);

#ifdef __cplusplus
};
#endif

#endif

