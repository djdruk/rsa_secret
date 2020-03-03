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

