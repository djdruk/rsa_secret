//
//  RSAcryptor.m
//  rsa_secret
//
//  Created by 张三 on 2020/3/2.
//  Copyright © 2020 张三. All rights reserved.
//

#import "RSAcryptor.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation RSAcryptor
static NSString *base64_encode_data(NSData *data){
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

static NSData *base64_decode(NSString *str){
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

/**
* -------从文件读取公钥-------
@param filePath 文件路径
@param size 文件大小
@return 返回密钥
*/
+ (SecKeyRef)getPublicKeyRefWithContentsOfFile:(NSString *)filePath keySize:(size_t )size
{
    SecKeyRef pubkeyref;
    NSError *readFErr = nil;
    CFErrorRef errref;
    NSString *pemStr = [NSString stringWithContentsOfFile:filePath encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr==nil, @"公钥文件加载失败");
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    NSData *dataPubKey = [[NSData alloc]initWithBase64EncodedString:pemStr options:0];
    NSMutableDictionary *dicPubkey = [[NSMutableDictionary alloc]initWithCapacity:1];
    [dicPubkey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dicPubkey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [dicPubkey setObject:@(size) forKey:(__bridge id)kSecAttrKeySizeInBits];
    pubkeyref = SecKeyCreateWithData((__bridge CFDataRef)dataPubKey, (__bridge CFDictionaryRef)dicPubkey, &errref);
    NSAssert(errref, @"公钥加载错误");
    return pubkeyref;
}

/**
* -------从文件读取私钥-------
@param filePath 文件路径
@param password 文件密码
@return 返回密钥
*/
+ (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSString *)filePath password:(NSString *)password {
    SecKeyRef prikeyRef;
    NSError *readFErr = nil;
    CFErrorRef err;
    NSString *pemStr = [NSString stringWithContentsOfFile:filePath encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr==nil, @"私钥文件加载失败");
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
    NSData *pemData = [[NSData alloc]initWithBase64EncodedString:pemStr options:0];
    
    NSMutableDictionary *dicPrikey = [[NSMutableDictionary alloc]initWithCapacity:1];
    [dicPrikey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dicPrikey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [dicPrikey setObject:password forKey:(__bridge id)kSecImportExportPassphrase];
//    [dicPrikey setObject:@(size) forKey:(__bridge id)kSecAttrKeySizeInBits];
    prikeyRef = SecKeyCreateWithData((__bridge CFDataRef)pemData, (__bridge CFDictionaryRef)dicPrikey, &err);
    NSAssert(err, @"私钥加载错误");
    return prikeyRef;
}


/**
* -------RSA 公钥加密-------
@param data 明文，待加密的数据
@param keyRef 公钥
@return 密文，加密后的数据
*/
+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

/**
* -------RSA 私钥解密-------
@param data 密文，需要解密的数据
@param keyRef 私钥
@return 明文，解密后的字符串
*/
+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }else{
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

/**
* -------私钥签名-------
@param plainData 明文
@param privateKey 私钥文件
@return 返回签名数据
*/
+ (NSData *)sianWithData:(NSData *)plainData secKeyRef:(SecKeyRef)privateKey {
    return PKCSSignBytesSHA256withRSA(plainData, privateKey);
}
NSData* PKCSSignBytesSHA256withRSA(NSData* plainData, SecKeyRef privateKey)
{
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

/**
* -------公钥校验签名-------
@param plainData 明文
@param signData 签名文件
@param publicKey 公钥文件
@return 验签成功返回YES，失败返回NO
*/
+ (BOOL)verifyWithData:(NSData *)plainData signature:(NSData *)signData secKeyRef:(SecKeyRef)publicKey {
    return PKCSVerifyBytesSHA256withRSA(plainData, signData, publicKey);
}

BOOL PKCSVerifyBytesSHA256withRSA(NSData* plainData, NSData* signature, SecKeyRef publicKey)
{
    if (!plainData || !signature) {
        return NO;
    }
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}


@end
