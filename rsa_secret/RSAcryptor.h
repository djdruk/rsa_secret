//
//  RSAcryptor.h
//  rsa_secret
//
//  Created by 张三 on 2020/3/2.
//  Copyright © 2020 张三. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAcryptor : NSObject

/**
* -------私钥签名-------
@param plainData 明文
@param privateKey 私钥文件
@return 返回签名数据
*/
+ (NSData *)sianWithData:(NSData *)plainData secKeyRef:(SecKeyRef)privateKey;

/**
* -------公钥校验签名-------
@param plainData 明文
@param signData 签名文件
@param publicKey 公钥文件
@return 验签成功返回YES，失败返回NO
*/
+ (BOOL)verifyWithData:(NSData *)plainData signature:(NSData *)signData secKeyRef:(SecKeyRef)publicKey;

/**
* -------从文件读取公钥-------
@param filePath 文件路径
@param size 文件大小
@return 返回密钥
*/
+ (SecKeyRef)getPublicKeyRefWithContentsOfFile:(NSString *)filePath keySize:(size_t )size;

/**
* -------从文件读取私钥-------
@param filePath 文件路径
@param password 文件密码
@return 返回密钥
*/
+ (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSString *)filePath password:(NSString *)password;

/**
* -------RSA 公钥加密-------
@param data 明文，待加密的数据
@param keyRef 公钥
@return 密文，加密后的数据
*/
+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef;

/**
* -------RSA 私钥解密-------
@param data 密文，需要解密的数据
@param keyRef 私钥
@return 明文，解密后的字符串
*/
+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef;




@end

NS_ASSUME_NONNULL_END
