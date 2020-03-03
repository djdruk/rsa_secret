#####签名验签
#####签名的一般过程：先对数据进行摘要计算，然后对摘要值用私钥进行签名。

#####RSA密钥签名验签
生成私钥。
>zhangsandeiMac:secret zhangsan$ openssl genrsa -out ca.key 2048

导出公钥。
>zhangsandeiMac:secret zhangsan$ openssl rsa -in ca.key -pubout -out ca.pub
writing RSA key

私钥签名。
>zhangsandeiMac:secret zhangsan$ openssl dgst -sign ca.key -sha256 -out 1.sign 1.zip 

公钥验签
>zhangsandeiMac:secret zhangsan$ openssl dgst -verify ca.pub -sha256 -signature 1.sign 1.zip 
Verified OK

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
