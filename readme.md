##### 签名验签
##### 签名的一般过程：先对数据进行摘要计算，然后对摘要值用私钥进行签名。

##### RSA密钥签名验签
生成私钥。
>zhangsandeiMac:secret zhangsan$ openssl genrsa -out ca.key 2048

导出公钥。
>zhangsandeiMac:secret zhangsan$ openssl rsa -in ca.key -pubout -out ca.pub


私钥签名。
>zhangsandeiMac:secret zhangsan$ openssl dgst -sign ca.key -sha256 -out 1.sign 1.zip 

公钥验签
>zhangsandeiMac:secret zhangsan$ openssl dgst -verify ca.pub -sha256 -signature 1.sign 1.zip 

<br/>
> /** <br/>
> * -------私钥签名-------<br/>
> @param plainData 明文<br/>
> @param privateKey 私钥文件<br/>
> @return 返回签名数据<br/>
> */
<br/>

```
+ (NSData *)sianWithData:(NSData *)plainData secKeyRef:(SecKeyRef)privateKey;
```

<br/>

> <br/>
> -------公钥校验签名-------<br/>
> @param plainData 明文<br/>
> @param signData 签名文件<br/>
> @param publicKey 公钥文件<br/>
> @return 验签成功返回YES，失败返回NO<br/>
> 
<br/>

```
+ (BOOL)verifyWithData:(NSData *)plainData signature:(NSData *)signData secKeyRef:(SecKeyRef)publicKey;
```
<br/>

> <br/>
> -------从文件读取公钥-------<br/>
> @param filePath 文件路径<br/>
> @param size 文件大小<br/>
> @return 返回密钥<br/>
> 
<br/>

```
+ (SecKeyRef)getPublicKeyRefWithContentsOfFile:(NSString *)filePath keySize:(size_t )size;
```

<br/>
> <br/>
> -------从文件读取私钥-------<br/>
> @param filePath 文件路径<br/>
> @param password 文件密码<br/>
> @return 返回密钥<br/>
>  
<br/>

```
+ (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSString *)filePath password:(NSString *)password;
```

<br/>
> <br/>
> * -------RSA 公钥加密-------<br/>
> @param data 明文，待加密的数据<br/>
> @param keyRef 公钥<br/>
> @return 密文，加密后的数据<br/>
> 
<br/>

```
+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef;
```

<br/>
> <br/>
> -------RSA 私钥解密-------<br/>
> @param data 密文，需要解密的数据<br/>
> @param keyRef 私钥<br/>
> @return 明文，解密后的字符串<br/>
> 
<br/>

```
+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef;
```

```object-c
    NSString *pubpem = [[NSBundle mainBundle] pathForResource:@"ca.pub" ofType:nil];
    SecKeyRef publicKeyRef = [RSAcryptor getPublicKeyRefWithContentsOfFile:pubpem keySize:1024];
        
    NSString *pripem = [[NSBundle mainBundle] pathForResource:@"ca.key" ofType:nil];
    SecKeyRef privateKeyRef = [RSAcryptor getPrivateKeyRefWithContentsOfFile:pripem password:@"1234"];
    
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"sign.zip" ofType:nil];
    NSData *data = [[NSData alloc] initWithContentsOfFile:filePath];

    NSData *signData = [RSAcryptor sianWithData:data secKeyRef:privateKeyRef];
    NSAssert([RSAcryptor verifyWithData:data signature:signData secKeyRef:publicKeyRef],@"验签失败");
    NSData *plainData = [data subdataWithRange:NSMakeRange(0, data.length-256)];
    NSData *signatureData = [data subdataWithRange:NSMakeRange(data.length-256, 256)];
    NSAssert([RSAHandleer verifyWithData:plainData signature:signatureData secKeyRef:publicKeyRef], @"签名失败");
    

    
    NSData *crptyData = [RSAcryptor encryptData:[@"phbtttttt@gmail.com" dataUsingEncoding:NSUTF8StringEncoding] withKeyRef:publicKeyRef];
    NSLog(@"crptyData = %@",crptyData);
    NSData *decryptData = [RSAcryptor decryptData:crptyData withKeyRef:privateKeyRef];
    NSLog(@"decryptData = %@", decryptData);
    NSLog(@"decryptString = %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);
```
