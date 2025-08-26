#include "testcases.h"
#include "sdf_bind.h"
#include "sdf_defs.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

testcase_t testcases[] = {
    {"Test_Device", Test_Device},
    {"Test_Session", Test_Session},
    {"Test_GetDeviceInfo", Test_GetDeviceInfo},
    {"Test_GenerateRandom", Test_GenerateRandom},
    {"Test_PrivateKeyAccessRight", Test_PrivateKeyAccessRight},
    {"Test_ExportSignPublicKey_RSA", Test_ExportSignPublicKey_RSA},
    {"Test_ExportEncPublic_RSA", Test_ExportEncPublic_RSA},
    {"Test_GenerateKeyWithIPK_RSA", Test_GenerateKeyWithIPK_RSA},
    {"Test_GenerateKeyWithEPK_RSA", Test_GenerateKeyWithEPK_RSA},
    {"Test_ImportKeyWithISK_RSA", Test_ImportKeyWithISK_RSA},
    {"Test_ExportSignPublicKey_ECC", Test_ExportSignPublicKey_ECC},
    {"Test_ExportEncPublicKey_ECC", Test_ExportEncPublicKey_ECC},
    {"Test_GenerateKeyWithIPK_ECC", Test_GenerateKeyWithIPK_ECC},
    {"Test_GenerateKeyWithEPK_ECC", Test_GenerateKeyWithEPK_ECC},
    {"Test_ImportKeyWithISK_ECC", Test_ImportKeyWithISK_ECC},
    {"Test_GenerateAgreementDataWithECC", Test_GenerateAgreementDataWithECC},
    {"Test_GenerateKeyWithECC", Test_GenerateKeyWithECC},
    {"Test_GenerateAgreementDataAndKeyWithECC", Test_GenerateAgreementDataAndKeyWithECC},
    {"Test_GenerateKeyWithKEK", Test_GenerateKeyWithKEK},
    {"Test_ImportKeyWithKEK", Test_ImportKeyWithKEK},
    {"Test_DestroyKey", Test_DestroyKey},
    {"Test_ExternalPublicKeyOperation_RSA", Test_ExternalPublicKeyOperation_RSA},
    {"Test_InternalPublicKeyOperation_RSA", Test_InternalPublicKeyOperation_RSA},
    {"Test_InternalPrivateKeyOperation_RSA", Test_InternalPrivateKeyOperation_RSA},
    {"Test_ExternalVerify_ECC", Test_ExternalVerify_ECC},
    {"Test_InternalSign_ECC", Test_InternalSign_ECC},
    {"Test_InternalVerify_ECC", Test_InternalVerify_ECC},
    {"Test_ExternalEncrypt_ECC", Test_ExternalEncrypt_ECC},
    {"Test_Encrypt", Test_Encrypt},
    {"Test_Decrypt", Test_Decrypt},
    {"Test_CalculateMAC", Test_CalculateMAC},
    {"Test_AuthEnc", Test_AuthEnc},
    {"Test_AuthDec", Test_AuthDec},
    {"Test_EncryptInit", Test_EncryptInit},
    {"Test_EncryptUpdate", Test_EncryptUpdate},
    {"Test_EncryptFinal", Test_EncryptFinal},
    {"Test_DecryptInit", Test_DecryptInit},
    {"Test_DecryptUpdate", Test_DecryptUpdate},
    {"Test_DecryptFinal", Test_DecryptFinal},
    {"Test_CalculateMACInit", Test_CalculateMACInit},
    {"Test_CalculateMACUpdate", Test_CalculateMACUpdate},
    {"Test_CalculateMACFinal", Test_CalculateMACFinal},
    {"Test_AuthEncInit", Test_AuthEncInit},
    {"Test_AuthEncUpdate", Test_AuthEncUpdate},
    {"Test_AuthEncFinal", Test_AuthEncFinal},
    {"Test_AuthDecInit", Test_AuthDecInit},
    {"Test_AuthDecUpdate", Test_AuthDecUpdate},
    {"Test_AuthDecFinal", Test_AuthDecFinal},
    {"Test_HMACInit", Test_HMACInit},
    {"Test_HMACUpdate", Test_HMACUpdate},
    {"Test_HMACFinal", Test_HMACFinal},
    {"Test_HashInit", Test_HashInit},
    {"Test_HashUpdate", Test_HashUpdate},
    {"Test_HashFinal", Test_HashFinal},
    {"Test_CreateFile", Test_CreateFile},
    {"Test_ReadFile", Test_ReadFile},
    {"Test_WriteFile", Test_WriteFile},
    {"Test_DeleteFile", Test_DeleteFile},
    {"Test_GenerateKeyPair_RSA", Test_GenerateKeyPair_RSA},
    {"Test_GenerateKeyPair_ECC", Test_GenerateKeyPair_ECC},
    {"Test_ExternalPrivateKeyOperation_RSA", Test_ExternalPrivateKeyOperation_RSA},
    {"Test_ExternalSign_ECC", Test_ExternalSign_ECC},
    {"Test_ExternalDecrypt_ECC", Test_ExternalDecrypt_ECC},
    {"Test_ExternalSign_SM9", Test_ExternalSign_SM9},
    {"Test_ExternalDecrypt_SM9", Test_ExternalDecrypt_SM9},
    {"Test_ExternalKeyEncrypt", Test_ExternalKeyEncrypt},
    {"Test_ExternalKeyDecrypt", Test_ExternalKeyDecrypt},
    {"Test_ExternalKeyEncryptInit", Test_ExternalKeyEncryptInit},
    {"Test_ExternalKeyDecryptInit", Test_ExternalKeyDecryptInit},
    {"Test_ExternalKeyHMACInit", Test_ExternalKeyHMACInit}
};
const int testcase_count = sizeof(testcases)/sizeof(testcases[0]);
int  Test_Device(){
    void *hDevice = NULL;
    int ret = OpenDevice(&hDevice);
    if (ret == SDR_OK) {
        printf("OpenDevice: %s\n", SDF_GetErrorString(ret));
        ret = CloseDevice(hDevice);
        if (ret == SDR_OK){
            printf("CloseDevice: %s\n", SDF_GetErrorString(ret));
        }else{
            printf("CloseDevice failed: %s\n", SDF_GetErrorString(ret));
        }
    } else {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
    }
    return ret;
}
int  Test_Session(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK) {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if (ret == SDR_OK){
        printf("OpenSession: %s\n", SDF_GetErrorString(ret));
    }
    else
    {
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = CloseSession(hSession);
    if (ret != SDR_OK){
        printf("CloseSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
cleanup:
    if(hSession){
        CloseSession(hSession);
    }
    if(hDevice){
        CloseDevice(hDevice);
    }
    return ret;
}
int Test_GetDeviceInfo(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if (ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    DEVICEINFO deviceInfo;
    ret = GetDeviceInfo(hSession, &deviceInfo);
    if (ret == 0) {
        printf("\n========== GetDeviceInfo: %s ==========\n", SDF_GetErrorString(ret));
        printf("IssuerName: %s\n", deviceInfo.IssuerName);
        printf("SerialNumber: %s\n", deviceInfo.SerialNumber);
        printf("FirmwareVersion: %s\n", deviceInfo.FirmwareVersion);
        printf("DeviceVersion: %u\n", deviceInfo.DeviceVersion);
        printf("StandardVersion: %u\n", deviceInfo.StandardVersion);
        printf("AsymAlgAbility: [%u, %u]\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
        printf("SymAlgAbility: %u\n", deviceInfo.SymAlgAbility);
        printf("HashAlgAbility: %u\n", deviceInfo.HashAlgAbility);
        printf("BufferSize: %u\n", deviceInfo.BufferSize);
        printf("===============================================\n");
    } else {
        printf("Failed GetDeviceInfo: %s\n", SDF_GetErrorString(ret));
    }
cleanup:
    if(hSession){
        CloseSession(hSession);
    }
    if(hDevice){
        CloseDevice(hDevice);
    }
    return ret;
}
int Test_GenerateRandom(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    int uiLength = 32;
    char buf[32];

    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if (ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = GenerateRandom(hSession, uiLength, buf);
    if (ret != SDR_OK) {
        printf("GenerateRandom failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    printf("GenerateRandom: %s\n", SDF_GetErrorString(ret));
    for (int i = 0; i < uiLength; i++) {
        printf("%02X ", (unsigned char)buf[i]);
    }
    printf("\n");
    

cleanup:
    if (hSession) {
        CloseSession(hSession);
    }
    if (hDevice) {
        CloseDevice(hDevice);
    }
    return ret;
}
int Test_PrivateKeyAccessRight(){
// softsdfinit -kek 1 -key 1 -pass P@ssw0rd
/*
    软实现会加载sm2enc-1.pem和sm2sign-1.pem
    用 pass（密码）对 PEM 格式的加密私钥文件进行解密，
    并把密钥内容加载到 container->enc_key 结构体中。
*/
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int KeyIndex = 1;
    char *password = "P@ssw0rd";
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = GetPrivateKeyAccessRight(hSession, KeyIndex, (unsigned char *)password, (unsigned int)strlen(password));
    printf("SDF_GetPrivateKeyAccessRight: %s\n", SDF_GetErrorString(ret));
    if(ret == SDR_OK){
        int r2 = ReleasePrivateKeyAccessRight(hSession, KeyIndex);
        printf("SDF_ReleasePrivateKeyAccessRight: %s\n", SDF_GetErrorString(r2));
        if(r2 != SDR_OK && ret == SDR_OK){
            ret = r2; // propagate failure
        }
    }
cleanup:
    if(hSession){
        CloseSession(hSession);
    }
    if(hDevice){
        CloseDevice(hDevice);
    }
    return ret;
}
int Test_ExportSignPublicKey_RSA(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int keyIndex = 1;
    RSArefPublicKey* pubKey = NULL;
    pubKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    if(!pubKey){
        printf("malloc pubKey failed\n");
        return -1;
    }
    memset(pubKey, 0, sizeof(RSArefPublicKey));
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = ExportSignPublicKey_RSA(hSession, keyIndex, pubKey);
    printf("ExportSignPublicKey_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pubKey){ free(pubKey);} 
    return ret;
}
int Test_ExportEncPublic_RSA(){
    int ret = -1;
    void* hDevice = NULL;
    void* hSession = NULL;
    unsigned int keyIndex = 1;
    RSArefPublicKey* pubKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    if(!pubKey){
        printf("malloc pubKey failed\n");
        return -1;
    }
    memset(pubKey, 0, sizeof(RSArefPublicKey));
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = ExportEncPublicKey_RSA(hSession, keyIndex, pubKey);
    printf("ExportEncPublicKey_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pubKey){ free(pubKey);} 
    return ret;
}
int Test_GenerateKeyWithIPK_RSA(){
    // 生成会话密钥并用内部RSA公钥加密输出
    // 应用场景：同一台加密机（HSM/SDF设备）上运行多个业务应用或进程，
    //          这些应用需要相互安全传递会话密钥，但密钥不能暴露给设备外部。
    /*
        密钥分三级：持久密钥，会话密钥，临时密钥
    内部的RSA公钥私钥对属于持久密钥：
        私钥在生成后会直接写入硬件安全模块（HSM/加密机/安全芯片）内部的受保护存储区。
    写入后：
    - 私钥不会导出到外部，也无法被普通业务系统读取或导出。
    - 只有硬件内部能使用私钥进行签名、解密等操作，外部只能通过keyIndex等引用方式调用。
    - 这样可以最大限度保证私钥安全，防止泄露。
    
    这里由于没有厂商库，GmSSL也没有软实现生成RSA密钥对的功能。为了模拟硬件：
    在sdf_defs.c里定义实现工具函数：SDF_GenerateKeyPair_RSA 生成公私钥对

    这里GmSSL的子项目softSDF提供了softsdfinit工具，使用当前目录下的.pem文件来模拟过程。
    */
    
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKey = NULL;
    
    // 密码设备存储的密钥对的索引值
    unsigned int IPKIndex = 1;
    char *password = "P@ssw0rd";
    unsigned int keyBits = 2048;
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    GetPrivateKeyAccessRight(hSession, IPKIndex, (unsigned char *)password, (unsigned int)strlen(password));
    // 缓冲区指针，用于存放返回的密钥密文
    unsigned char *pucKey = NULL;
    // 返回的密钥密文长度
    unsigned int *pubKeyLength = NULL;

    // hKey：返回的会话密钥句柄，用于后续使用这个会话密钥

    pucKey = (unsigned char*)malloc(256);
    pubKeyLength = (unsigned int*)malloc(sizeof(unsigned int));
    if(!pucKey || !pubKeyLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    *pubKeyLength = 256; memset(pucKey,0,256);
    ret = GenerateKeyWithIPK_RSA(hSession, IPKIndex, keyBits, pucKey, pubKeyLength, &hKey);
    printf("GenerateKeyWithIPK_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucKey) free(pucKey);
    if(pubKeyLength) free(pubKeyLength);
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    return ret;
}
int Test_GenerateKeyWithEPK_RSA(){
    // 生成会话密钥，并用外部RSA公钥加密输出
    // 应用场景：当你需要将会话密钥安全地传递给另一个系统、设备或远程端时，
    //          必须用对方的公钥加密密钥后输出，防止密钥在传输过程中被窃取。
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKey = NULL;
    unsigned int keyIndex = 1;
    char *password = "P@ssw0rd";
    unsigned int keyBits = 2048;
    RSArefPublicKey *pucPublicKey = NULL;
    unsigned char *pucKey = NULL;
    unsigned int *pubKeyLength = NULL;
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    GetPrivateKeyAccessRight(hSession, keyIndex, (unsigned char *)password, (unsigned int)strlen(password));
    pucPublicKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    pucKey = (unsigned char*)malloc(256);
    pubKeyLength = (unsigned int*)malloc(sizeof(unsigned int));
    if(!pucPublicKey || !pucKey || !pubKeyLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucPublicKey,0,sizeof(RSArefPublicKey)); memset(pucKey,0,256); *pubKeyLength = 256;
    ret = GenerateKeyWithEPK_RSA(hSession, keyBits, pucPublicKey,pucKey,pubKeyLength, &hKey);
    printf("GenerateKeyWithEPK_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    if(pucKey){ free(pucKey);} 
    if(pubKeyLength){ free(pubKeyLength);} 
    return ret;
}
int Test_ImportKeyWithISK_RSA(){
    // 导入会话密钥并用内部RSA私钥解密
    // chord to GenerateKeyWithEPK_RSA
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    // 密码设备存储的密钥对的索引值
    unsigned int ISKIndex = 1;

    // 缓冲区指针，用于存放输入的密钥密文
    unsigned char *pucKey = NULL;
    unsigned int puiKeyLength = 0;
    void * phKeyHandle = NULL;
    GetPrivateKeyAccessRight(hSession, ISKIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    // 由于GenerateKeyWithEPK_RSA未被softsdf实现
    // unsigned char *pucKey;
    // pucKey = (unsigned char *)malloc(1024);
    // GenerateKeyWithEPK_RSA(hSession, ISKIndex, (unsigned char *)"P@ssw0rd",(unsigned int)strlen("P@ssw0rd"))
    pucKey = (unsigned char*)malloc(256); if(!pucKey){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucKey,0,256); puiKeyLength = 256;
    ret = ImportKeyWithISK_RSA(hSession,ISKIndex,pucKey,puiKeyLength,phKeyHandle);
    printf("ImportKeyWithISK_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucKey) free(pucKey);
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    return ret;
}
int Test_ExportSignPublicKey_ECC(){
    // 导出密码设备内部存储的指定索引位置的ECC签名公钥
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int KeyIndex = 1;
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if(!pucPublicKey){
        printf("malloc public key failed\n");
        return -1;
    }
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExportSignPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    printf("ExportSignPublicKey_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    return ret;
}
int Test_ExportEncPublicKey_ECC(){
    // 导出密码设备内部存储的指定索引位置的ECC加密公钥
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int KeyIndex = 1;
    ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if(!pucPublicKey){ printf("malloc public key failed\n"); return -1; }
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExportEncPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    printf("ExportEncPublicKey_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    return ret;
}
int Test_GenerateKeyWithIPK_ECC(){
    // 生成会话密钥并用内部ECC公钥加密输出
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    unsigned int IPKIndex = 1;
    unsigned int KeyBits = 128; // 但国密规定SM4密钥长度只用128。

    // 早期C语言的匈牙利命名法：pucKey => pointer to unsigned char => unsigned char *
    // GenerateKeyWithIPK_RSA里边的这个pucKey指针是unsigned char *，这里变成了ECCCipher *
    // RSA密文简单，直接用byte array 
    // ECC密文复杂，标准希望开发者直接用结构体，避免手动拆解/拼装字段，减少出错。
    ECCCipher *pucKey = NULL;
    pucKey = (ECCCipher *)malloc(sizeof(ECCCipher));
    void *phKeyHandle = NULL;
    ret = GenerateKeyWithIPK_ECC(hSession, IPKIndex,KeyBits, pucKey, &phKeyHandle);
    printf("GenerateKeyWithIPK_ECC:%s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucKey){ free(pucKey);} 
    return ret;
}
int Test_GenerateKeyWithEPK_ECC(){
    //生成会话密钥并用外部ECC公钥加密输出，同时返回密钥句柄。
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 用来指定用哪种ECC算法/曲线/用途 来处理该公钥
    // 具体定义在GM/T 0006
    /*
        #define SGD_SM2			0x00020100
        #define SGD_SM2_1		0x00020200 // SM2 Signature Scheme
        #define SGD_SM2_2		0x00020400 // SM2 Key Exchange Protocol
        #define SGD_SM2_3		0x00020800 // SM2 Encryption Scheme
    */
    unsigned int uiAlgID = 0x00020800;
    // 外部ECC公钥结构
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    unsigned int KeyIndex = 1;

    // memset(pucPublicKey,0,sizeof(ECCrefPublicKey));
    // 缓冲区指针，用于存放返回的密钥密文
    ECCCipher *pucKey = NULL;
    pucKey = (ECCCipher *)malloc(sizeof(ECCCipher));
    void *phKeyHandle = NULL;
    unsigned int KeyBits = 128;
    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ExportEncPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    ret = GenerateKeyWithEPK_ECC(hSession,KeyBits,uiAlgID, pucPublicKey, pucKey, &phKeyHandle);
    printf("GenerateKeyWithEPK_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    if(pucKey){ free(pucKey);} 
    return ret;
}
int Test_ImportKeyWithISK_ECC(){
    // 导入会话密钥并用内部ECC加密私钥进行解密，同时返回密钥句柄

    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int ISKIndex = 1;
    unsigned int KeyIndex = 1;
    char *password = "P@ssw0rd";
    void *phKeyHandle = NULL;

    ECCCipher *pucKey = NULL;
    pucKey = (ECCCipher *)malloc(sizeof(ECCCipher));
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    unsigned int AlgID = 0x00020800;
    unsigned int KeyBits = 128;

    ret = OpenDevice(&hDevice);
    if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession);
    if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    // 缓冲区指针，用于存放输入的密钥密文

    ExportEncPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    GenerateKeyWithEPK_ECC(hSession, KeyBits, AlgID, pucPublicKey, pucKey, &phKeyHandle);

    GetPrivateKeyAccessRight(hSession, ISKIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    ret = ImportKeyWithISK_ECC(hSession, ISKIndex, pucKey, &phKeyHandle);
    printf("ImportKeyWithISK_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} 
    if(hDevice){ CloseDevice(hDevice);} 
    if(pucKey){ free(pucKey);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    return ret;
}
int Test_GenerateAgreementDataWithECC(){
    // 使用ECC密钥协商算法，为计算会话密钥而产生协商参数，
    // 同时返回指定索引位置的ECC公钥、临时ECC密钥对的公钥及协商句柄。
    // 协商会话密钥时，本函数首先由协商方发起调用。
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int ISKIndex = 1;
    unsigned int KeyBits = 256;

    // 发起方ID与长度
    unsigned char *SponsorID = NULL;
    unsigned int SponsorIDLength = 16;
    ECCrefPublicKey *pSponsorPublicKey = NULL;
    ECCrefPublicKey *pSponsorTmpPublicKey = NULL;
    void *phAgreementHandle = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); return ret; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    SponsorID = (unsigned char*)malloc(SponsorIDLength);
    pSponsorPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    pSponsorTmpPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    if(!SponsorID || !pSponsorPublicKey || !pSponsorTmpPublicKey){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(SponsorID,0xA1,SponsorIDLength);
    ret = GenerateAgreementDataWithECC(hSession, ISKIndex, KeyBits, SponsorID, SponsorIDLength,pSponsorPublicKey, pSponsorTmpPublicKey, &phAgreementHandle);
    printf("GenerateAgreementDataWithECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pSponsorPublicKey) free(pSponsorPublicKey); if(pSponsorTmpPublicKey) free(pSponsorTmpPublicKey); if(SponsorID) free(SponsorID);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_GenerateKeyWithECC(){
    // 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥
    // 同时返回会话密钥句柄
    // 使用SM2算法计算会话密钥的过程应符合 GB/T 35276
    // 本函数由协商的发起方在获得响应方的协商参数后调用
    // 会话密钥计算完成后，协商句柄被销毁
    // 为协商句柄分配的内存资源也被释放
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned char *ResponseID = NULL;
    unsigned int ResponseIDLength = 16;
    ECCrefPublicKey *pucResponsePublicKey = NULL;
    ECCrefPublicKey *pucResponseTmpPublicKey = NULL;
    void *hAgreementHandle = NULL;
    void *phKeyHandle = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); return ret; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ResponseID = (unsigned char*)malloc(ResponseIDLength);
    pucResponsePublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    pucResponseTmpPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    if(!ResponseID || !pucResponsePublicKey || !pucResponseTmpPublicKey){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(ResponseID,0xB2,ResponseIDLength);
    ret = GenerateKeyWithECC(hSession, ResponseID, ResponseIDLength, pucResponsePublicKey, pucResponseTmpPublicKey, hAgreementHandle, &phKeyHandle);
    printf("GenerateKeyWithECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucResponsePublicKey) free(pucResponsePublicKey); if(pucResponseTmpPublicKey) free(pucResponseTmpPublicKey); if(ResponseID) free(ResponseID);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_GenerateAgreementDataAndKeyWithECC(){
    // 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥
    // 同时返回会话密钥句柄，同时返回会话密钥句柄
    // 使用SM2算法计算会话密钥的过程应符合 GB/T 35276
    // 本函数由响应方调用
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int ISKIndex = 1;
    unsigned int uiKeyBits = 128;
    unsigned char *pucResponseID = NULL; unsigned int uiResponseIDLength = 16;
    unsigned char *pucSponsorID = NULL; unsigned int uiSponsorIDLength = 16;
    ECCrefPublicKey *pucSponsorPublicKey = NULL; ECCrefPublicKey *pucSponsorTmpPublicKey = NULL;
    ECCrefPublicKey *pucResponsePublicKey = NULL; ECCrefPublicKey *pucResponseTmpPublicKey = NULL;
    void *phKeyHandle = NULL;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); return ret; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucResponseID = (unsigned char*)malloc(uiResponseIDLength); pucSponsorID = (unsigned char*)malloc(uiSponsorIDLength);
    pucSponsorPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey)); pucSponsorTmpPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    pucResponsePublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey)); pucResponseTmpPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    if(!pucResponseID || !pucSponsorID || !pucSponsorPublicKey || !pucSponsorTmpPublicKey || !pucResponsePublicKey || !pucResponseTmpPublicKey){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucResponseID,0xC3,uiResponseIDLength); memset(pucSponsorID,0xC4,uiSponsorIDLength);
    ret = GenerateAgreementDataAndKeyWithECC(
        hSession,
        ISKIndex,
        uiKeyBits,
        pucResponseID,
        uiResponseIDLength,
        pucSponsorID,
        uiSponsorIDLength,
        pucSponsorPublicKey,
        pucSponsorTmpPublicKey,
        pucResponsePublicKey,
        pucResponseTmpPublicKey,
        &phKeyHandle
        );
    printf("GenerateAgreementDataAndKeyWithECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucSponsorPublicKey) free(pucSponsorPublicKey); if(pucSponsorTmpPublicKey) free(pucSponsorTmpPublicKey); if(pucResponsePublicKey) free(pucResponsePublicKey); if(pucResponseTmpPublicKey) free(pucResponseTmpPublicKey); if(pucResponseID) free(pucResponseID); if(pucSponsorID) free(pucSponsorID);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_GenerateKeyWithKEK(){
    // 生成会话密钥并用密钥加密密钥加密输出
    // 同时返回密钥句柄，加密模式为CBC模式
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    // #define SGD_SM4			0x00000400
    // #define SGD_CBC			0x02
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned int uiKEKIndex = 1;
    // unsigned char *pucKey;
    unsigned int uiKeyBits = 128; // 或256，按需求
    unsigned char *pucKey;        // 足够大，通常32~64字节
    unsigned int *puiKeyLength;
    pucKey = (unsigned char *)malloc(64);
    puiKeyLength = (unsigned int *)malloc(sizeof(unsigned int));
    void *phKeyHandle = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    GetPrivateKeyAccessRight(hSession,uiKEKIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    ret = GenerateKeyWithKEK(hSession, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &phKeyHandle);
    printf("GenerateKeyWithKEK: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} if(pucKey){ free(pucKey);} if(puiKeyLength){ free(puiKeyLength);} return ret;
}
int Test_ImportKeyWithKEK(){
    // 导入会话密钥并用加密密钥解密
    

      // 先用GenerateKeyWithKEK生成会话密钥并用密钥加密密钥加密输出
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    // #define SGD_SM4			0x00000400
    // #define SGD_CBC			0x02
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned int uiKEKIndex = 1;
    // unsigned char *pucKey;
    unsigned int uiKeyBits = 128; // 或256，按需求
    unsigned char *pucKey;        // 足够大，通常32~64字节
    unsigned int *puiKeyLength;
    pucKey = (unsigned char *)malloc(64);
    puiKeyLength = (unsigned int *)malloc(sizeof(unsigned int));
    void *phKeyHandle = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    GetPrivateKeyAccessRight(hSession,uiKEKIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    GenerateKeyWithKEK(hSession, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &phKeyHandle);
    ret = ImportKeyWithKEK(hSession, uiAlgID, uiKEKIndex, pucKey, *puiKeyLength, &phKeyHandle);
    printf("ImportKeyWithKEK: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} if(pucKey){ free(pucKey);} if(puiKeyLength){ free(puiKeyLength);} return ret;
}
int Test_DestroyKey(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *phKeyHandle = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    // 借用GenerateKeyWithKEK对KeyHandle模拟赋值
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned int uiKEKIndex = 1;
    unsigned int uiKeyBits = 128; 
    unsigned char *pucKey;        
    unsigned int *puiKeyLength;
    pucKey = (unsigned char *)malloc(64);
    puiKeyLength = (unsigned int *)malloc(sizeof(unsigned int));
    GetPrivateKeyAccessRight(hSession,uiKEKIndex, (char *)"P@ssw0rd",sizeof((char *)"P@ssw0rd"));
    GenerateKeyWithKEK(hSession, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &phKeyHandle);

    ret = DestroyKey(hSession, phKeyHandle);
    printf("DestroyKey: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} if(pucKey){ free(pucKey);} if(puiKeyLength){ free(puiKeyLength);} return ret;
}
int Test_ExternalPublicKeyOperation_RSA(){
    // 指定使用外部公钥对数据进行RSA运算，数据格式由应用层封装
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 外部RSA公钥结构
    RSArefPublicKey *pucPublicKey = NULL;
    unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0;
    unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucPublicKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int));
    if(!pucPublicKey || !pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucPublicKey,0,sizeof(RSArefPublicKey)); memset(pucDataInput,0x11,32); *puiOutputLength = 256;
    ret = ExternalPublicKeyOperation_RSA(hSession, pucPublicKey, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
    printf("ExternalPublicKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucPublicKey) free(pucPublicKey); if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_InternalPublicKeyOperation_RSA(){
    // 使用内部指定索引的公钥对数据进行RSA运算，
    // 索引范围仅限于内部签名密钥对，数据格式应由应用层封装

    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    /// 密码设备存储的密钥对的索引
    unsigned int uiKeyIndex = 1;
    // 缓冲区指针，用于存放外部输入的数据
    unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0;
    unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; memset(pucDataInput,0x22,32);
    pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int)); if(!pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; } *puiOutputLength = 256;
    ret = InternalPublicKeyOperation_RSA(hSession,uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
    printf("InternalPublicKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_InternalPrivateKeyOperation_RSA(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiKeyIndex = 1;
    unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0; unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; memset(pucDataInput,0x33,32);
    pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int)); if(!pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; } *puiOutputLength = 256;
    ret = InternalPrivateKeyOperation_RSA(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
    printf("InternalPrivateKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_ExternalVerify_ECC(){
    // 使用外部公钥对ECC签名值进行验证运算
    // 输入数据为待签数据的杂凑值
    // 当使用SM2算法时，该输入数据经过SM2签名预处理的结果
    // SM2算法预处理过程应符合 GB/T 35276


    // 公钥=> ExportSignPublicKey_ECC
    // 摘要=> SDF_HashInit/Update/Final 
    // 签名=> InternalSign_ECC
    // 验签=> ExternalVerify_ECC

    // 验签时，必须同时拿到“数据摘要”和“签名值”，才能判断签名是否有效。
    // 因此，有两个指向输入数据的指针
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    //    #define SGD_SM2_1		0x00020200 // SM2 Signature Scheme
    unsigned int uiAlgID = 0x00020200 ;
    // 外部ECC公钥结构
    ECCrefPublicKey *pucPublicKey = NULL;
    // 缓冲区指针，用于存放外部输入的数据
    unsigned char *pucDataInput = NULL;
    // 输入的数据长度
    unsigned int uiInputLength = 32;
    // 缓冲区指针，用于存放输入的签名值数据
    ECCSignature *pucSignature = NULL;
    unsigned int uiKeyIndex = 1;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    // printf("==========DEBUG============\n");
    // printf("pucPublicKey->bits: %d\n", pucPublicKey->bits);
    //     printf("==========DEBUG============\n");
    pucDataInput = (unsigned char *)malloc(uiInputLength);
    pucSignature = (ECCSignature*)malloc(sizeof(ECCSignature));
    if(!pucPublicKey || !pucDataInput || !pucSignature){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucDataInput,0x55,uiInputLength); memset(pucSignature,0,sizeof(ECCSignature));
    ret = GetPrivateKeyAccessRight(hSession,uiKeyIndex,(char *)("P@ssw0rd"), strlen("P@ssw0rd")); if(ret != SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = InternalSign_ECC(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucSignature); if(ret != SDR_OK){ printf("InternalSign_ECC failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExportSignPublicKey_ECC(hSession, uiKeyIndex, pucPublicKey); if(ret != SDR_OK){printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));goto cleanup;}

    ret = ExternalVerify_ECC(hSession, uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature);
    printf("ExternalVerify_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucPublicKey) free(pucPublicKey); if(pucDataInput) free(pucDataInput); if(pucSignature) free(pucSignature);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_InternalSign_ECC(){
    // 使用内部指定索引的私钥对数据进行ECC签名运算。
    // 输入数据为待签数据的杂凑值。
    // 当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果
    // SM2算法预处理过程应符合 GB/T 35276
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 密码设备存储的密钥对的索引值
    unsigned int uiISKIndex = 1;
    // 缓冲区指针，用于存储外部输入的数据
    unsigned char *pucData = NULL;
    // 输入的数据长度
    unsigned int uiDataLength = 32;
    // 缓冲区指针，用于存放输出的签名值数据
    ECCSignature * pucSignature = NULL;
    // 输入数据准备：
    /*
        // 伪代码
        SDF_HashInit(hSession, SGD_SM3, pucPublicKey, pucID, uiIDLength);
        SDF_HashUpdate(hSession, message, messageLen);
        SDF_HashFinal(hSession, digest, &digestLen);
        // digest 就是“SM2签名预处理”后的杂凑值
        SDF_InternalSign_ECC(hSession, keyIndex, digest, digestLen, &signature);
    //如果你的软实现不支持自动做Z值拼接，你需要自己用GmSSL等库先做Z值拼接和SM3。
    */
    // unsigned char message[] = "test message";
    // unsigned char digest[32];
    // unsigned int digestLen = 32;
    // SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0);
    // SDF_HashUpdate(hSession, message, strlen((char*)message));
    // SDF_HashFinal(hSession, digest, &digestLen);
    // ECCSignature *pucSignature = malloc(sizeof(ECCSignature));
    // int ret = InternalSign_ECC(hSession, uiISKIndex, digest, digestLen, pucSignature);


    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = GetPrivateKeyAccessRight(hSession, uiISKIndex, (char *)("P@ssw0rd"), strlen("P@ssw0rd")); if(ret != SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucData = (unsigned char *)malloc(uiDataLength);
    pucSignature = (ECCSignature *)malloc(sizeof(ECCSignature));
    if(!pucData || !pucSignature){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucData,0x66,uiDataLength); memset(pucSignature,0,sizeof(ECCSignature));
    // 一般是对数据的哈希值进行签名，这里为了测试方便，直接mock数据哈希值来签名
    ret = InternalSign_ECC(hSession,uiISKIndex,pucData,uiDataLength,pucSignature);
    printf("InternalSign_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucData) free(pucData); if(pucSignature) free(pucSignature);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
}
int Test_InternalVerify_ECC(){
    // 使用内部指定索引的公钥对ECC签名值进行验证运算
    // 输入数据为待签数据的杂凑值
    // 当使用SM2算法时，该输入数据经过SM2签名预处理的结果
    // SM2算法预处理过程应符合 GB/T 35276
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 密码设备存储的密钥对的索引值
    unsigned int uiKeyIndex = 1;
    // 缓冲区指针，用于存放外部输入的数据
    unsigned char *pucDataInput = NULL;
    // 输入的数据长度
    unsigned int uiInputLength = 32;
    // 缓冲区指针，用于存放输入的签名值数据
    ECCSignature *pucSignature = NULL;
    unsigned int uiISKIndex = 1;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucDataInput = (unsigned char*)malloc(uiInputLength); pucSignature = (ECCSignature*)malloc(sizeof(ECCSignature));
    if(!pucDataInput || !pucSignature){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucDataInput,0x77,uiInputLength); 
    ret = GetPrivateKeyAccessRight(hSession, uiISKIndex, (char *)("P@ssw0rd"), strlen("P@ssw0rd")); if(ret != SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = InternalSign_ECC(hSession,uiISKIndex,pucDataInput,uiInputLength,pucSignature); if(ret != SDR_OK){ printf("InternalSign_ECC failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = InternalVerify_ECC(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucSignature); 
    printf("InternalVerify_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucDataInput) free(pucDataInput); if(pucSignature) free(pucSignature);
    if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} return ret;
    return ret;
}
int Test_ExternalEncrypt_ECC(){
    // 使用外部ECC公钥对数据进行ECC加密运算
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // #define SGD_SM2_3		0x00020800 // SM2 Encryption Scheme
    unsigned int uiAlgID = 0x00020800 ;
    unsigned int uiKeyIndex = 1;
    // 外部ECC公钥结构
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    // 缓冲区指针，用于存放输入的数据
    unsigned char *pucDataInput = NULL;
    // 输入的数据长度(按位<256)
    unsigned int uiInputLength = 32;
    // 缓冲区指针，用于存放输出的数据
    ECCCipher *pucDataOutput = NULL;
    pucDataOutput = (ECCCipher *)malloc(sizeof(ECCCipher));


    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    unsigned char *password = "P@ssw0rd";
    GetPrivateKeyAccessRight(hSession, uiKeyIndex,password,strlen((char*)password));
    ExportEncPublicKey_ECC(hSession,uiKeyIndex, pucPublicKey);
    pucDataInput = (unsigned char*)malloc(uiInputLength);
    if(!pucDataInput){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucDataInput,0x88,uiInputLength);
    ret = ExternalEncrypt_ECC(hSession, uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucDataOutput);
    printf("ExternalEncrypt_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucDataInput) free(pucDataInput); if(hSession){ CloseSession(hSession);} if(hDevice){ CloseDevice(hDevice);} if(pucPublicKey){ free(pucPublicKey);} if(pucDataOutput){ free(pucDataOutput);} return ret;
}
int Test_Encrypt(){
    // 使用指定的密钥句柄和IV对数据进行对称加密运算
    // 此函数不对数据进行填充处理，此函数的IV数据长度与算法分组长度相同
    void *hSession = NULL;
    void *hDevice = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x02);
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    unsigned int uiDataLength;
    unsigned char *pucIV;
    unsigned char *pucData;
    unsigned char *pucEncData;
    unsigned int *puiEncDataLength;
    int ret = -1;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
    if (!pucIV){
        goto cleanup;
    }
    memset(pucIV, 0, 16);

    uiDataLength = 32;
    pucData = malloc(uiDataLength);
    memset(pucData, 0x11, uiDataLength);

    pucEncData = malloc(uiDataLength + 16);
    puiEncDataLength = malloc(sizeof(unsigned int));
    *puiEncDataLength = uiDataLength + 16;

    unsigned char *pucKey = malloc(64);
    unsigned int uiKEKIndex = 1;
    unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
    void *hKeyHandle = NULL;

    ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != SDR_OK)
    {
        printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
    printf("SymmetricEncrypt: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    if(pucKey) free(pucKey);
    if(pucData) free(pucData);
    if(pucEncData) free(pucEncData);
    if(puiEncDataLength) free(puiEncDataLength);
    if(puiKeyLength) free(puiKeyLength);
    if(hSession) CloseSession(hSession);
    if(hDevice) CloseDevice(hDevice);
    return ret;
}
int Test_Decrypt(){
    // 使用指定的密钥句柄和IV对数据进行对称解密运算。
    // 此函数的IV数据长度与算法分组长度相同
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned char *pucIV;
    unsigned char *pucEncData;
    unsigned int uiEncDataLength;
    unsigned char *pucDataDecrypted;
    unsigned int *puiDataLengthDecrypted;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    
    
    
    pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
    if (!pucIV){
        goto cleanup;
    }
    memset(pucIV, 0, 16);

    // 加密前数据长度
    unsigned int uiDataLength = 32;
    unsigned char *pucData = malloc(uiDataLength);
    memset(pucData, 0x11, uiDataLength);

    pucEncData = malloc(uiDataLength + 16);
    // 加密后数据长度
    unsigned int * puiEncDataLength = malloc(sizeof(unsigned int));
    *puiEncDataLength = uiDataLength + 16;

    unsigned char *pucKey = malloc(64);
    unsigned int uiKEKIndex = 1;
    unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
    ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != SDR_OK)
    {
        printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
    if (ret != SDR_OK)
    {
        printf("Encrypt failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    // 解密后数据长度
    pucDataDecrypted = malloc(*puiEncDataLength);
    puiDataLengthDecrypted = malloc(sizeof(unsigned int));

    // pucEncData = pucEncData;
    uiEncDataLength = *puiEncDataLength;

    ret = Decrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucDataDecrypted, puiDataLengthDecrypted);
    printf("SymmetricDecrypt: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    if(pucKey) free(pucKey);
    if(pucData) free(pucData);
    if(pucEncData) free(pucEncData);
    if(puiEncDataLength) free(puiEncDataLength);
    if(puiKeyLength) free(puiKeyLength);
    if(pucDataDecrypted) free(pucDataDecrypted);
    if(puiDataLengthDecrypted) free(puiDataLengthDecrypted);
    if(hSession) CloseSession(hSession);
    if(hDevice) CloseDevice(hDevice);
    return ret;
}
int Test_CalculateMAC(){
    // 使用指定的密钥句柄和IV对数据进行对称加密MAC运算，
    // 此函数不对数据进行填充处理
    // MAC算法标识和工作模式的约定同分组密码算法
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x10 );
    unsigned char *pucIV = NULL;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucMAC = NULL;
    unsigned int *puiMacLength = NULL;

    ret = OpenDevice(&hDevice); if( ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if( ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }


    unsigned char *pucKey = malloc(64);
    unsigned int uiKEKIndex = 1;
    unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
    uiAlgID = (0x00000400 | 0x02);
    ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != SDR_OK)
    {
        printf("GenerateKeyWithKEK failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    uiAlgID = (0x00000400 | 0x10 );
    uiDataLength = 32;

    pucData = malloc(uiDataLength);
    memset(pucData, 0x11, uiDataLength);
    pucMAC = malloc(16);
    puiMacLength = malloc(sizeof(unsigned int));
    *puiMacLength = 16;
    ret = CalculateMAC(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMacLength);
    printf("CalculateMAC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    if(pucData) free(pucData);
    if(pucKey) free(pucKey);
    if(puiKeyLength) free(puiKeyLength);
    if(puiMacLength) free(puiMacLength);
    if(pucMAC) free(pucMAC);
    if(hSession) CloseSession(hSession);
    if(hDevice) CloseDevice(hDevice);
    return ret;
}
int Test_AuthEnc(){
    // 使用指定的密钥句柄对数据进行可鉴别加密运算
    // 此函数应用于可鉴别加密的CCM和GCM模式
    // 输入输出数据应根据GM/T 0006 定义的算法标识并按照 GB/T 36624的规定进行确定
    int ret = -1;
    void *hSession = NULL;
    void *hDevice = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = 0; // 占位符
    unsigned int uiStartVarLength = 12; unsigned int uiAadLength = 16; unsigned int uiDataLength = 32;
    unsigned char *pucStartVar = (unsigned char*)malloc(uiStartVarLength);
    unsigned char *pucAad = (unsigned char*)malloc(uiAadLength);
    unsigned char *pucData = (unsigned char*)malloc(uiDataLength);
    unsigned int *puiEncDataLength = (unsigned int*)malloc(sizeof(unsigned int));
    unsigned int *puiAuthDataLength = (unsigned int*)malloc(sizeof(unsigned int));
    unsigned char *pucEncData = NULL; unsigned char *pucAuthData = NULL;
    if(!pucStartVar || !pucAad || !pucData || !puiEncDataLength || !puiAuthDataLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucStartVar,0x01,uiStartVarLength); memset(pucAad,0x02,uiAadLength); memset(pucData,0x03,uiDataLength);
    *puiEncDataLength = uiDataLength + 16; *puiAuthDataLength = 16;
    pucEncData = (unsigned char*)malloc(*puiEncDataLength); pucAuthData = (unsigned char*)malloc(*puiAuthDataLength);
    if(!pucEncData || !pucAuthData){ printf("malloc failed\n"); ret = -1; goto cleanup; }

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    // printf("hSession: %p\n", hSession);
    // int ret = 0;
    ret = AuthEnc(
        hSession,
        hKeyHandle,
        uiAlgID,
        pucStartVar,
        uiStartVarLength,
        pucAad,
        uiAadLength,
        pucData,
        uiDataLength,
        pucEncData,
        puiEncDataLength,
        pucAuthData,
        puiAuthDataLength);
    printf("AuthEnc: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucStartVar) free(pucStartVar); if(pucAad) free(pucAad); if(pucData) free(pucData); if(pucEncData) free(pucEncData); if(puiEncDataLength) free(puiEncDataLength); if(pucAuthData) free(pucAuthData); if(puiAuthDataLength) free(puiAuthDataLength);
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthDec(){
    // 使用指定的密钥句柄对数据进行可鉴别解密运算
    // 此函数应用于可鉴别解密的CCM和GCM模式
    int ret = -1;
    void *hSessionHandle = NULL;
    void *hDevice = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = 0;
    unsigned int uiStartVarLength = 12, uiAadLength = 16; unsigned int uiAuthDataLenIn = 16; unsigned int puiEncDataLength = 48;
    unsigned char *pucStartVar = (unsigned char*)malloc(uiStartVarLength);
    unsigned char *pucAad = (unsigned char*)malloc(uiAadLength);
    unsigned char *pucAuthData = (unsigned char*)malloc(uiAuthDataLenIn);
    unsigned int *puiAuthDataLength = (unsigned int*)malloc(sizeof(unsigned int));
    unsigned char *pucEncData = (unsigned char*)malloc(puiEncDataLength);
    unsigned char *pucData = NULL; unsigned int *puiDataLength = NULL;
    if(!pucStartVar || !pucAad || !pucAuthData || !puiAuthDataLength || !pucEncData){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucStartVar,0x04,uiStartVarLength); memset(pucAad,0x05,uiAadLength); memset(pucAuthData,0x06,uiAuthDataLenIn); *puiAuthDataLength = uiAuthDataLenIn;
    puiDataLength = (unsigned int*)malloc(sizeof(unsigned int)); *puiDataLength = puiEncDataLength;
    pucData = (unsigned char*)malloc(*puiDataLength); if(!pucData){ printf("malloc failed\n"); ret = -1; goto cleanup; }

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSessionHandle); if (ret != SDR_OK){ printf("OpenSession failed: %s", SDF_GetErrorString(ret)); goto cleanup; }
    ret = AuthDec(
        hSessionHandle,
        hKeyHandle,
        uiAlgID,
        pucStartVar,
        uiStartVarLength,
        pucAad,
        uiAadLength,
        pucAuthData,
        puiAuthDataLength,
        pucEncData,
        puiEncDataLength,
        pucData,
        puiDataLength);
    printf("AuthDec: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucStartVar) free(pucStartVar); if(pucAad) free(pucAad); if(pucAuthData) free(pucAuthData); if(puiAuthDataLength) free(puiAuthDataLength); if(pucEncData) free(pucEncData); if(pucData) free(pucData); if(puiDataLength) free(puiDataLength);
    if(hSessionHandle) CloseSession(hSessionHandle); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_EncryptInit(){
    // 多包对称加密初始化，设置加密密钥句柄
    //
    int ret = 0;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned char *pucIV = NULL;
    unsigned int uiIVLength = 16;

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    // 生成一个对称密钥句柄供后续使用
    unsigned char *tmpKey = (unsigned char*)malloc(64); unsigned int *tmpKeyLen = (unsigned int*)malloc(sizeof(unsigned int)); if(!tmpKey || !tmpKeyLen){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, 1, tmpKey, tmpKeyLen, &hKeyHandle);
    if(ret != SDR_OK){ printf("GenerateKeyWithKEK failed: %s\n", SDF_GetErrorString(ret)); }
    pucIV = (unsigned char*)malloc(uiIVLength); if(pucIV){ memset(pucIV,0,uiIVLength);} else { printf("malloc IV failed\n"); }
    ret = EncryptInit(hSession, hKeyHandle, uiAlgID, pucIV, uiIVLength);
    printf("EncryptInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    // tmpKey and tmpKeyLen freed implicitly here
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_EncryptUpdate(){
    // 对多包数据进行对称加密运算，此函数不对数据进行填充处理
    int ret = -1; void *hDevice = NULL; void *hSession = NULL;
    unsigned int uiDataLength = 32;
    unsigned char *pucData = (unsigned char*)malloc(uiDataLength);
    unsigned int *puiEncDataLength = (unsigned int*)malloc(sizeof(unsigned int));
    unsigned char *pucEncData = NULL;
    if(!pucData || !puiEncDataLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucData,0x09,uiDataLength); *puiEncDataLength = uiDataLength + 16; pucEncData = (unsigned char*)malloc(*puiEncDataLength); if(!pucEncData){ printf("malloc failed\n"); ret = -1; goto cleanup; }

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = EncryptUpdate(
        hSession,
        pucData,
        uiDataLength,
        pucEncData,
        puiEncDataLength);
    printf("EncryptUpdate:%s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucData) free(pucData); if(pucEncData) free(pucEncData); if(puiEncDataLength) free(puiEncDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_EncryptFinal(){
    // 多包对称加密结束，处理最后一块数据，释放相关资源
    // 输出的最后部分密文可以为空 
    int ret = -1; void *hDevice = NULL; void *hSession = NULL;
    unsigned int *puiLastEncDataLength = (unsigned int*)malloc(sizeof(unsigned int));
    unsigned char *pucLastEncData = NULL;
    if(puiLastEncDataLength){ *puiLastEncDataLength = 32; pucLastEncData = (unsigned char*)malloc(*puiLastEncDataLength); if(pucLastEncData) memset(pucLastEncData,0,*puiLastEncDataLength); }

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = EncryptFinal(hSession, pucLastEncData, puiLastEncDataLength);
    printf("EncryptFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucLastEncData) free(pucLastEncData); if(puiLastEncDataLength) free(puiLastEncDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_DecryptInit(){
    // 多包数据解密初始化，设置解密密钥句柄，IV和算法标识
    int ret = -1; void *hDevice = NULL; void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x02);
    // 指向输入的IV数据
    unsigned char *pucIV = NULL;
    unsigned int uiIVLength = 16;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    unsigned char *tmpKey = (unsigned char*)malloc(64); unsigned int *tmpKeyLen = (unsigned int*)malloc(sizeof(unsigned int)); if(!tmpKey || !tmpKeyLen){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, 1, tmpKey, tmpKeyLen, &hKeyHandle);
    if(ret != SDR_OK){ printf("GenerateKeyWithKEK failed: %s\n", SDF_GetErrorString(ret)); }
    pucIV = (unsigned char*)malloc(uiIVLength); if(pucIV) memset(pucIV,0,uiIVLength);
    ret = DecryptInit(hSession, hKeyHandle, uiAlgID, pucIV, uiIVLength);
    printf("DecryptInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_DecryptUpdate(){
    // 对多包数据进行对称解密运算
    int ret = -1; void *hDevice = NULL; void *hSession = NULL;
    // 缓冲区指针，用于存放输入数据的密文
    unsigned int uiEncDataLength = 48; unsigned char *pucEncData = (unsigned char*)malloc(uiEncDataLength);
    unsigned int *puiDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucData = NULL;
    if(!pucEncData || !puiDataLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    memset(pucEncData,0x0A,uiEncDataLength); *puiDataLength = uiEncDataLength;
    pucData = (unsigned char*)malloc(*puiDataLength); if(!pucData){ printf("malloc failed\n"); ret = -1; goto cleanup; }

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = DecryptUpdate(hSession, pucEncData, uiEncDataLength, pucData, puiDataLength);
    printf("DecryptUpdate: %s\n", SDF_GetErrorString(ret));

cleanup:
    if(pucEncData) free(pucEncData); if(pucData) free(pucData); if(puiDataLength) free(puiDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_DecryptFinal(){
    // 多包对称解密结束，释放相关资源
    // 输出的最后部分明文可以为空
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 缓冲区指针,释放相关资源，输出的最后部分明文可以为空
    unsigned int *puiLastDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucLastData = NULL;
    if(puiLastDataLength){ *puiLastDataLength = 48; pucLastData = (unsigned char*)malloc(*puiLastDataLength); if(pucLastData) memset(pucLastData,0,*puiLastDataLength); }

    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if (ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        CloseDevice(hDevice);
        goto cleanup;
    }
    ret = DecryptFinal(hSession, pucLastData, puiLastDataLength);
    printf("DecryptFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucLastData) free(pucLastData); if(puiLastDataLength) free(puiLastDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_CalculateMACInit(){
    // 多包对称MAC初始化，设置MAC密钥句柄，IV和算法标识
    // 对称MAC算法标识的约定同分组密码算法
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = (0x00000400 | 0x10);
    unsigned char *pucIV = NULL; unsigned int uiIVLength = 16;
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    unsigned char *tmpKey = (unsigned char*)malloc(64); unsigned int *tmpKeyLen = (unsigned int*)malloc(sizeof(unsigned int)); if(!tmpKey || !tmpKeyLen){ printf("malloc failed\n"); ret = -1; goto cleanup; }
    // 使用CBC生成句柄占位
    unsigned int genAlg = (0x00000400 | 0x02);
    GenerateKeyWithKEK(hSession, 128, genAlg, 1, tmpKey, tmpKeyLen, &hKeyHandle);
    pucIV = (unsigned char*)malloc(uiIVLength); if(pucIV) memset(pucIV,0,uiIVLength);
    ret = CalculateMACInit(
        hSession,
        hKeyHandle,
        uiAlgID,
        pucIV,
        uiIVLength);
    printf("CalculateMACInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_CalculateMACUpdate(){
    // 多包MAC计算
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 缓冲区指针，用于存放输入的数据
    unsigned int uiDataLength = 32; unsigned char *pucData = (unsigned char*)malloc(uiDataLength); if(pucData){ memset(pucData,0x0B,uiDataLength);} else { printf("malloc failed\n"); ret = -1; }
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = CalculateMACUpdate(hSession, pucData, uiDataLength);
    printf("CalculateMACUpdate: %s\n", SDF_GetErrorString(ret));

cleanup:
    if(pucData) free(pucData); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_CalculateMACFinal(){
    int ret = -1; void *hDevice = NULL; void *hSession = NULL;
    unsigned int *puiMacLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucMac = NULL; if(puiMacLength){ *puiMacLength = 16; pucMac = (unsigned char*)malloc(*puiMacLength); if(pucMac) memset(pucMac,0,*puiMacLength);} else { printf("malloc failed\n"); ret = -1; }
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = CalculateMACFinal(hSession, pucMac, puiMacLength);
    printf("CalculateMACFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucMac) free(pucMac); if(puiMacLength) free(puiMacLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthEncInit(){
    // 多包数据可鉴别加密初始化，设置加密密钥句柄、算法标识、开始变量、额外的可鉴别数据
    // 此函数应用于可鉴别加密的CCM和GCM模式，
    // 输入输出数据应按照 GM/T 0006 定义的算法标识和 GB/T 36624 的规定进行确定
    // GCM模式下的数据明文总长度参数可为空
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = 0; unsigned int uiStartVarLength = 12; unsigned int uiAadLength = 16; unsigned int uiDataLength = 32;
    unsigned char *pucStartVar = (unsigned char*)malloc(uiStartVarLength);
    unsigned char *pucAad = (unsigned char*)malloc(uiAadLength);
    if(pucStartVar) memset(pucStartVar,0x0C,uiStartVarLength); if(pucAad) memset(pucAad,0x0D,uiAadLength);

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    ret = AuthEncInit(
        hSession,
        hKeyHandle,
        uiAlgID,
        pucStartVar,
        uiStartVarLength,
        pucAad,
        uiAadLength,
        uiDataLength);
    printf("AuthEncInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucStartVar) free(pucStartVar); if(pucAad) free(pucAad); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthEncUpdate(){
    // 对多包数据进行可鉴别加密运算。
    // 此函数的输出不包括鉴别数据
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiDataLength = 32; unsigned char *pucData = (unsigned char*)malloc(uiDataLength); unsigned int *puiEncDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucEncData = NULL;
    if(pucData) memset(pucData,0x0E,uiDataLength); if(puiEncDataLength){ *puiEncDataLength = uiDataLength + 16; pucEncData = (unsigned char*)malloc(*puiEncDataLength); if(pucEncData) memset(pucEncData,0,*puiEncDataLength);} else { ret = -1; }

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = AuthEncUpdate(hSession, pucData, uiDataLength, pucEncData, puiEncDataLength);
    printf("AuthEncUpdate: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucData) free(pucData); if(pucEncData) free(pucEncData); if(puiEncDataLength) free(puiEncDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthEncFinal(){
    // 多包可鉴别加密结束，释放相关资源
    // 此函数的输出数据应按照 GM/T 0006定义的算法标识和 GB/T 36624 的规定进行输出
    // 输出的最后部分密文可为空
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int *puiLastEncDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucLastEncData = NULL; unsigned int *puiAuthDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucAuthData = NULL;
    if(puiLastEncDataLength){ *puiLastEncDataLength = 16; pucLastEncData = (unsigned char*)malloc(*puiLastEncDataLength); if(pucLastEncData) memset(pucLastEncData,0,*puiLastEncDataLength);} if(puiAuthDataLength){ *puiAuthDataLength = 16; pucAuthData = (unsigned char*)malloc(*puiAuthDataLength); if(pucAuthData) memset(pucAuthData,0,*puiAuthDataLength); }
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    ret = AuthEncFinal(
        hSession,
        pucLastEncData,
        puiLastEncDataLength,
        pucAuthData,
        puiAuthDataLength);
    printf("AuthEncFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucLastEncData) free(pucLastEncData); if(puiLastEncDataLength) free(puiLastEncDataLength); if(pucAuthData) free(pucAuthData); if(puiAuthDataLength) free(puiAuthDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthDecInit(){
    // 多包数据可鉴别解密初始化，设置解密密钥句柄，算法标识，开始变量，额外的可鉴别数据
    // 此函数应用于可鉴别解密的 CCM 和 GCM 模式
    // 输入输出数据应该按照 GM/T 0006 定义的算法标识和 GB/T 36624的规定进行确定
    // GCM 模式下的数据明文总长度参数可为空
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = 0; unsigned int uiStartVarLength = 12; unsigned int uiAadLength = 16; unsigned int uiAuthDataLength = 16; unsigned int uiDataLength = 32;
    unsigned char *pucStartVar = (unsigned char*)malloc(uiStartVarLength);
    unsigned char *pucAad = (unsigned char*)malloc(uiAadLength);
    unsigned char *pucAuthData = (unsigned char*)malloc(uiAuthDataLength);
    if(pucStartVar) memset(pucStartVar,0x0F,uiStartVarLength); if(pucAad) memset(pucAad,0x10,uiAadLength); if(pucAuthData) memset(pucAuthData,0x11,uiAuthDataLength);

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = AuthDecInit(
        hSession,
        hKeyHandle,
        uiAlgID,
        pucStartVar,
        uiStartVarLength,
        pucAad,
        uiAadLength,
        pucAuthData,
        uiAuthDataLength,
        uiDataLength);
    printf("AuthDecInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucStartVar) free(pucStartVar); if(pucAad) free(pucAad); if(pucAuthData) free(pucAuthData); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthDecUpdate(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiEncDataLength = 48; unsigned char *pucEncData = (unsigned char*)malloc(uiEncDataLength); unsigned int *puiDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucData = NULL;
    if(pucEncData) memset(pucEncData,0x12,uiEncDataLength); if(puiDataLength){ *puiDataLength = uiEncDataLength; pucData = (unsigned char*)malloc(*puiDataLength); }

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = AuthDecUpdate(
        hSession, 
        pucEncData, 
        uiEncDataLength, 
        pucData, 
        puiDataLength);
    printf("AuthDecUpdate: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucEncData) free(pucEncData); if(pucData) free(pucData); if(puiDataLength) free(puiDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_AuthDecFinal(){
    // 多包可鉴别解密结束，释放相关资源
    // 输出的最后部分明文可为空
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int *puiLastDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucLastData = NULL; if(puiLastDataLength){ *puiLastDataLength = 48; pucLastData = (unsigned char*)malloc(*puiLastDataLength); if(pucLastData) memset(pucLastData,0,*puiLastDataLength); }

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = AuthDecFinal(hSession, pucLastData, puiLastDataLength);
    printf("AuthDecFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucLastData) free(pucLastData); if(puiLastDataLength) free(puiLastDataLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HMACInit(){
    // 三步式带密钥的数据杂凑运算第一步。
    // 本函数执行带密钥的杂凑运算过程应符合 GB/T 15852.2
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL; unsigned int uiAlgID = 0;
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    unsigned char *tmpKey = (unsigned char*)malloc(64); unsigned int *tmpKeyLen = (unsigned int*)malloc(sizeof(unsigned int)); if(tmpKey && tmpKeyLen){ GenerateKeyWithKEK(hSession, 128, (0x00000400|0x02), 1, tmpKey, tmpKeyLen, &hKeyHandle); }
    ret = HMACInit(hSession,hKeyHandle,uiAlgID);
    printf("HMACInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HMACUpdate(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiDataLength = 32; unsigned char *pucData = (unsigned char*)malloc(uiDataLength); if(pucData) memset(pucData,0x13,uiDataLength);

    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = HMACUpdate(hSession, pucData, uiDataLength);
cleanup:
    if(pucData) free(pucData); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HMACFinal(){
    // 三步式带密钥的数据杂凑运算第三步，
    // 杂凑运算结束返回杂凑数据并清楚中间数据
    // 本函数执行带密钥的杂凑运算过程应符合 GB/T 15852.2
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int *puiHMacLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucHMac = NULL; if(puiHMacLength){ *puiHMacLength = 32; pucHMac = (unsigned char*)malloc(*puiHMacLength); if(pucHMac) memset(pucHMac,0,*puiHMacLength); }
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = HMACFinal(hSession, pucHMac, puiHMacLength);
    printf("HMACFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucHMac) free(pucHMac); if(puiHMacLength) free(puiHMacLength); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HashInit(){
    // 三步式杂凑运算第一步
    // uiIDLength非零且uiAlgID为 SGD_SM3时，
    // 本函数执行的是SM2的预处理 1 操作
    // 此时pucPublicKey 不能为空，
    // SM2算法预处理过程应符合 GB/T 35276
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey)); 
    unsigned int uiIDLength = 16; 
    unsigned char *pucID = (unsigned char*)malloc(uiIDLength); 
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    if(pucID) memset(pucID,0x14,uiIDLength); 
    if(pucPublicKey){
        unsigned int uiKeyIndex = 1;
        ret = ExportEncPublicKey_ECC(hSession,uiKeyIndex,pucPublicKey);
        if (ret != SDR_OK){
            printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }
    }
    // #define SGD_SM3			0x00000001
    unsigned int uiAlgID = 0x00000001;
    // printf("==================DEBUG================\n");
    // printf("uiAlgID=%x\n", uiAlgID);
    // printf("==================DEBUG================\n");
    ret = HashInit(hSession, uiAlgID, pucPublicKey, pucID, uiIDLength);
    printf("HashInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucPublicKey) free(pucPublicKey); if(pucID) free(pucID); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HashUpdate(){
    // 三步式杂凑运算第二部，对输入的明文进行杂凑运算
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiAlgID = 0x00000001;
    unsigned int uiIDLength = 16;
    unsigned char *pucID = NULL;
    unsigned int uiDataLength = 32;
    unsigned char *pucData = (unsigned char *)malloc(uiDataLength);
    if (pucData)memset(pucData, 0x15, uiDataLength);
    ret = OpenDevice(&hDevice); if (ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if (ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if(pucPublicKey){
        int uiKeyIndex = 1;
        ret = ExportEncPublicKey_ECC(hSession,uiKeyIndex,pucPublicKey);
        if (ret != SDR_OK){
            printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }

        pucID = (unsigned char*)malloc(uiIDLength);
        if (pucID) {memset(pucID, 0x14, uiIDLength);}else{
            goto cleanup;
        }
        ret = HashInit(hSession, uiAlgID, pucPublicKey, pucID, uiIDLength);
        if (ret != SDR_OK){
            printf("HashInit failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }

    }
    ret = HashUpdate(hSession, pucData, uiDataLength);
    printf("HashUpdate: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucData) free(pucData); if(hSession) CloseSession(hSession); if(pucID) free(pucID); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_HashFinal(){
    // 三步式杂凑运算第三步，杂凑运算结束返回杂凑数据并清楚中间数据
    // 本函数执行带密钥的杂凑运算过程应符合 GB/T 15852.2
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int *puiHashLength = (unsigned int*)malloc(sizeof(unsigned int)); 
    unsigned char *pucHash = NULL; 
    unsigned int uiAlgID = 0x00000001;
    unsigned int uiIDLength = 16;
    unsigned char *pucID = NULL;
    unsigned int uiDataLength = 32;
    unsigned char *pucData;
    if (puiHashLength)
    {
        *puiHashLength = 32; 
        pucHash = (unsigned char*)malloc(*puiHashLength); 
        if(pucHash) memset(pucHash,0,*puiHashLength);
    }
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    unsigned int uiKeyIndex = 1;
    ECCrefPublicKey* pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
    if(pucPublicKey){
        ret = ExportEncPublicKey_ECC(hSession,uiKeyIndex,pucPublicKey);
        if (ret != SDR_OK){
            printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }
        pucID = (unsigned char*)malloc(uiIDLength);
        if (pucID) {memset(pucID, 0x14, uiIDLength);}else{
            goto cleanup;
        }
        pucData = (unsigned char *)malloc(uiDataLength);
        if (pucData) {memset(pucData, 0x15, uiDataLength);}else{
            goto cleanup;
        }
        ret = HashInit(hSession, uiAlgID, pucPublicKey, pucID, uiIDLength);
        if (ret != SDR_OK){
            printf("HashInit failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }
        ret = HashUpdate(hSession, pucData, uiDataLength);
        if (ret != SDR_OK){
            printf("HashUpdate failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }
        ret = HashFinal(hSession, pucHash, puiHashLength);
        if (ret != SDR_OK){
            printf("HashFinal failed: %s\n", SDF_GetErrorString(ret));
            goto cleanup;
        }

    }
    printf("HashFinal: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucHash) free(pucHash); if(puiHashLength) free(puiHashLength);if(pucPublicKey) free(pucPublicKey);
    if(pucID) free(pucID); if(pucData) free(pucData);
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_CreateFile(){
    // 在密码设备内部创建用于存储用户的数据文件
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    char *pucFileName = "test.txt";
    unsigned int uiNameLen = 7;
    unsigned int uiFileSize = 1024;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = CreateFile(
        hSession, 
        pucFileName,
        uiNameLen,
        uiFileSize
    );
    printf("CreateFile: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_ReadFile(){
    // 读取在密码设备内部存储用户数据文件的内容
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // 指定读取文件时的偏移
  
    char *pucFileName = "test.txt";
    unsigned int uiNameLen = 7;  
    unsigned int uiOffset = 0;
    unsigned int *puiFileLength = NULL;
    puiFileLength = (unsigned int *)malloc(sizeof(unsigned int));
    if (puiFileLength == NULL)
    {
        printf("malloc failed\n");
        goto cleanup;
    }
    *puiFileLength = 1024;
    unsigned char *pucBuffer = NULL;
    pucBuffer = (unsigned char *)malloc(*puiFileLength);
    if (pucBuffer == NULL)
    {
        printf("malloc failed\n");
        goto cleanup;
    }
    
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ReadFile(
        hSession,
        pucFileName,
        uiNameLen,
        uiOffset,
        puiFileLength,
        pucBuffer        
    );
    printf("ReadFile: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); if(pucBuffer) free(pucBuffer); if(puiFileLength) free(puiFileLength); return ret;
}
int Test_WriteFile(){
    // 向密码设备内部存储用户数据的文件中写入内容
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    char *pucFileName = "test.txt";
    unsigned int uiNameLen = 7;
    unsigned int uiOffset = 0;
    unsigned int uiFileLength = 1024;
    unsigned char *pucBuffer = NULL;
    pucBuffer = (unsigned char *)malloc(uiFileLength);
    if (pucBuffer == NULL) {
        printf("malloc failed\n");
        goto cleanup;
    }

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = WriteFile(
        hSession,
        pucFileName,
        uiNameLen,
        uiOffset,
        uiFileLength,
        pucBuffer);
    printf("WriteFile: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); if(pucBuffer) free(pucBuffer); return ret;
}
int Test_DeleteFile(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    char *pucFileName = "test.txt";
    unsigned int uiNameLen = 7;

    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = DeleteFile(
        hSession,
        pucFileName,
        uiNameLen
    );
    printf("DeleteFile: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_GenerateKeyPair_RSA(){
    int ret = -1; void *hDevice = NULL; void *hSession = NULL; unsigned int uiKeyBits; RSArefPublicKey *pucPublicKey = NULL; RSArefPrivateKey *pucPrivateKey = NULL;
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = GenerateKeyPair_RSA(uiKeyBits,pucPublicKey,pucPrivateKey);
    printf("GenerateKeyPair_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_GenerateKeyPair_ECC(){
    int ret = -1; void *hDevice = NULL; void *hSession = NULL; unsigned int uiAlgID; unsigned int uiKeyBits; ECCrefPublicKey *pucPublicKey = NULL; ECCrefPrivateKey *pucPrivateKey = NULL;
    uiAlgID = 0x00020200;
    /*
        #define SGD_SM2_1		0x00020200 // SM2 Signature Scheme
        #define SGD_SM2_2		0x00020400 // SM2 Key Exchange Protocol
        #define SGD_SM2_3		0x00020800 // SM2 Encryption Scheme
    */
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey)); 
    pucPrivateKey = (ECCrefPrivateKey *)malloc(sizeof(ECCrefPrivateKey));
    uiKeyBits = 256;
    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK)
    {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = GenerateKeyPair_ECC(uiAlgID,uiKeyBits,pucPublicKey,pucPrivateKey);
    printf("GenerateKeyPair: %s\n",SDF_GetErrorString(ret));
cleanup:
    if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_ExternalPrivateKeyOperation_RSA(){
    RSArefPrivateKey *pucPrivateKey = (RSArefPrivateKey*)malloc(sizeof(RSArefPrivateKey));
    unsigned int uiInputLength = 32; unsigned char *pucDataInput = (unsigned char*)malloc(uiInputLength);
    unsigned int *puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucDataOutput = NULL;
    if(pucPrivateKey) memset(pucPrivateKey,0,sizeof(RSArefPrivateKey)); if(pucDataInput) memset(pucDataInput,0x16,uiInputLength); if(puiOutputLength){ *puiOutputLength = 256; pucDataOutput = (unsigned char*)malloc(*puiOutputLength); }
    int ret = ExternalPrivateKeyOperation_RSA(
        pucPrivateKey,
        pucDataInput,
        uiInputLength,
        pucDataOutput,
        puiOutputLength);
    printf("ExternalPrivateKeyOperation: %s\n",SDF_GetErrorString(ret));
    if(pucPrivateKey) free(pucPrivateKey); if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
    return ret;
}
int Test_ExternalSign_ECC(){
    // 指定使用外部ECC私钥对数据进行签名运算。
    // 当使用SM2算法时，该输入数据为代签数据经过SM2签名预处理的结果
    // SM2算法预处理过程应符合 GB/T 35276
    unsigned int uiAlgID = 0x00020200; ECCrefPrivateKey *pucPrivateKey = (ECCrefPrivateKey*)malloc(sizeof(ECCrefPrivateKey)); unsigned int uiInputLength = 32; unsigned char *pucDataInput = (unsigned char*)malloc(uiInputLength); ECCSignature *pucSignature = (ECCSignature*)malloc(sizeof(ECCSignature));
    if(pucPrivateKey) memset(pucPrivateKey,0,sizeof(ECCrefPrivateKey)); if(pucDataInput) memset(pucDataInput,0x17,uiInputLength); if(pucSignature) memset(pucSignature,0,sizeof(ECCSignature));

    int ret = ExternalSign_ECC(
        uiAlgID,
        pucPrivateKey,
        pucDataInput,
        uiInputLength,
        pucSignature);
    printf("ExternalSign_ECC: %s\n", SDF_GetErrorString(ret));
    if(pucPrivateKey) free(pucPrivateKey); if(pucDataInput) free(pucDataInput); if(pucSignature) free(pucSignature);
    return ret;
}
int Test_ExternalDecrypt_ECC(){
    // 指定使用外部ECC私钥对数据进行解密运算
    unsigned int uiAlgID = 0x00020800; ECCrefPrivateKey *pucPrivateKey = (ECCrefPrivateKey*)malloc(sizeof(ECCrefPrivateKey)); ECCCipher *pucEncData = (ECCCipher*)malloc(sizeof(ECCCipher)); unsigned int *uiDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucData = NULL; if(uiDataLength){ *uiDataLength = 64; pucData = (unsigned char*)malloc(*uiDataLength); }
    if(pucPrivateKey) memset(pucPrivateKey,0,sizeof(ECCrefPrivateKey)); if(pucEncData) memset(pucEncData,0,sizeof(ECCCipher)); if(pucData) memset(pucData,0,*uiDataLength);
    int ret = ExternalDecrypt_ECC(
        uiAlgID,
        pucPrivateKey,
        pucEncData,
        pucData,
        uiDataLength);
    printf("ExternalDecrypt_ECC: %s\n",SDF_GetErrorString(ret));
    if(pucPrivateKey) free(pucPrivateKey); if(pucEncData) free(pucEncData); if(pucData) free(pucData); if(uiDataLength) free(uiDataLength);

    return ret;
}
int Test_ExternalSign_SM9(){
    // 使用外部签名主公钥和外部SM9用户名签名私钥对数据进行签名运算
    // 输入数据为带签数据的SM3杂凑值
    SM9SignMasterPublicKey *pSignMastPublicKey = NULL;
    SM9SignUserPrivateKey *pSignUserPrivateKey = NULL;
    unsigned char *pucData;
    unsigned int uiDataLength;
    SM9Signature *pSignature;

    int ret = ExternalSign_SM9(
        pSignMastPublicKey,
        pSignUserPrivateKey,
        pucData,
        uiDataLength,
        pSignature);
    printf("ExternalSign_SM9: %s\n", SDF_GetErrorString(ret));

    return ret;
}
int Test_ExternalDecrypt_SM9(){
    // 使用用户加密密钥对(包括用户私钥和用户标识)对数据进行解密运算
    SM9EncUserPrivateKey *pEncUserPrivateKey = NULL;
    unsigned char *pucUserID;
    unsigned int uiUserIDLen;
    unsigned char *pucIV;
    unsigned char *pucData;
    unsigned int uiDataLength;
    SM9Cipher *pEncData;

    int ret = ExternalDecrypt_SM9(
        pEncUserPrivateKey,
        pucUserID,
        uiUserIDLen,
        pucIV,
        pucData,
        uiDataLength,
        pEncData
    );
    printf("ExternalDecrypt_SM9: %s\n", SDF_GetErrorString(ret));
    return ret;
}
int Test_ExternalKeyEncrypt(){
    // 使用外部密钥和IV对数据进行对称加密运算，此函数不对数据进行填充处理
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned int uiKeyLength = 16; unsigned char *pucKey = (unsigned char*)malloc(uiKeyLength); unsigned int uiIVLength = 16; unsigned char *pucIV = (unsigned char*)malloc(uiIVLength);
    unsigned int uiDataLength = 32; unsigned char *pucData = (unsigned char*)malloc(uiDataLength); unsigned int *puiEncDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucEncData = NULL;
    if(pucKey) memset(pucKey,0x18,uiKeyLength); if(pucIV) memset(pucIV,0x19,uiIVLength); if(pucData) memset(pucData,0x1A,uiDataLength); if(puiEncDataLength){ *puiEncDataLength = uiDataLength + 16; pucEncData = (unsigned char*)malloc(*puiEncDataLength); if(pucEncData) memset(pucEncData,0,*puiEncDataLength);} 

    int ret = ExternalKeyEncrypt(
        uiAlgID,
        pucKey,
        uiKeyLength,
        pucIV,
        uiIVLength,
        pucData,
        uiDataLength,
        pucEncData,
        puiEncDataLength
    );
    printf("ExternalKeyEncrypt: %s\n", SDF_GetErrorString(ret));
    if(pucKey) free(pucKey); if(pucIV) free(pucIV); if(pucData) free(pucData); if(pucEncData) free(pucEncData); if(puiEncDataLength) free(puiEncDataLength);
    return ret;
}
int Test_ExternalKeyDecrypt(){
    unsigned int uiAlgID = (0x00000400 | 0x02);
    unsigned int uiKeyLength = 16; unsigned char *pucKey = (unsigned char*)malloc(uiKeyLength); unsigned int uiIVLength = 16; unsigned char *pucIV = (unsigned char*)malloc(uiIVLength);
    unsigned int uiEncDataLength = 48; unsigned char *pucEncData = (unsigned char*)malloc(uiEncDataLength); unsigned int *puiDataLength = (unsigned int*)malloc(sizeof(unsigned int)); unsigned char *pucData = NULL;
    if(pucKey) memset(pucKey,0x1B,uiKeyLength); if(pucIV) memset(pucIV,0x1C,uiIVLength); if(pucEncData) memset(pucEncData,0x1D,uiEncDataLength); if(puiDataLength){ *puiDataLength = uiEncDataLength; pucData = (unsigned char*)malloc(*puiDataLength); if(pucData) memset(pucData,0,*puiDataLength);} 

    int ret = ExternalKeyDecrypt(
        uiAlgID,
        pucKey,
        uiKeyLength,
        pucIV,
        uiIVLength,
        pucData,
        uiEncDataLength,
        pucEncData,
        puiDataLength
    );
    printf("ExternalKeyDecrypt: %s\n", SDF_GetErrorString(ret));
    if(pucKey) free(pucKey); if(pucIV) free(pucIV); if(pucEncData) free(pucEncData); if(pucData) free(pucData); if(puiDataLength) free(puiDataLength);
    return ret;
}
int Test_ExternalKeyEncryptInit(){
    // 使用外部密钥的多包数据加密初始化
    // 设置加密密钥、IV和算法标识
    int ret = -1; void *hDevice = NULL; void *hSession = NULL; unsigned int uiAlgID = (0x00000400 | 0x02); unsigned int uiKeyLength = 16; unsigned char *pucKey = (unsigned char*)malloc(uiKeyLength); unsigned int uiIVLength = 16; unsigned char *pucIV = (unsigned char*)malloc(uiIVLength); if(pucKey) memset(pucKey,0x1E,uiKeyLength); if(pucIV) memset(pucIV,0x1F,uiIVLength);
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExternalKeyEncryptInit(hSession, uiAlgID, pucKey, uiKeyLength, pucIV, uiIVLength);
    printf("ExternalKeyEncryptInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucKey) free(pucKey); if(pucIV) free(pucIV); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_ExternalKeyDecryptInit(){
    int ret = -1; void *hDevice = NULL; void *hSession = NULL; unsigned int uiAlgID = (0x00000400 | 0x02); unsigned int uiKeyLength = 16; unsigned char *pucKey = (unsigned char*)malloc(uiKeyLength); unsigned int uiIVLength = 16; unsigned char *pucIV = (unsigned char*)malloc(uiIVLength); if(pucKey) memset(pucKey,0x20,uiKeyLength); if(pucIV) memset(pucIV,0x21,uiIVLength);
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExternalKeyDecryptInit(hSession, uiAlgID, pucKey, uiKeyLength, pucIV, uiIVLength);
    printf("ExternalKeyDecryptInit: %s\n",SDF_GetErrorString(ret));
cleanup:
    if(pucKey) free(pucKey); if(pucIV) free(pucIV); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}
int Test_ExternalKeyHMACInit(){
    // 三步式带密钥的杂凑运算第一步
    int ret = -1; void *hDevice = NULL; void *hSession = NULL; unsigned int uiAlgID = 0; unsigned int uiKeyLength = 16; unsigned char *pucKey = (unsigned char*)malloc(uiKeyLength); if(pucKey) memset(pucKey,0x22,uiKeyLength);
    ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = ExternalKeyHMACInit(hSession, uiAlgID, pucKey, uiKeyLength);
    printf("ExternalKeyHMACInit: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucKey) free(pucKey); if(hSession) CloseSession(hSession); if(hDevice) CloseDevice(hDevice); return ret;
}


void Test_all(){
    printf("testcase_count: %d\n", testcase_count);
    for (int i = 0; i < testcase_count; ++i)
    {
        int ret = testcases[i].func();
        if (ret == SDR_OK){
            pass++;
            printf("\033[32m[PASS]\033[0m %s\n", testcases[i].name);
        } else if( ret == SDR_NOTSUPPORT){
            notsupport++;
            printf("\033[33m[FAIL: %s] \033[0m%s\n",SDF_GetErrorString(ret),testcases[i].name);
        }else{
            fail++;
            printf("\033[31m[FAIL: %s] \033[0m%s\n",SDF_GetErrorString(ret),testcases[i].name);
        }
    }
}