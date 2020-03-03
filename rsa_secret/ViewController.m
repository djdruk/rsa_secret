//
//  ViewController.m
//  rsa_secret
//
//  Created by 张三 on 2020/3/2.
//  Copyright © 2020 张三. All rights reserved.
//

#import "ViewController.h"
#import "RSAcryptor.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    NSString *pubpem = [[NSBundle mainBundle] pathForResource:@"ca.pub" ofType:nil];
    SecKeyRef publicKeyRef = [RSAcryptor getPublicKeyRefWithContentsOfFile:pubpem keySize:1024];
        
    NSString *pripem = [[NSBundle mainBundle] pathForResource:@"ca.key" ofType:nil];
    SecKeyRef privateKeyRef = [RSAcryptor getPrivateKeyRefWithContentsOfFile:pripem password:@"1234"];
    
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"sign.zip" ofType:nil];
    NSData *data = [[NSData alloc] initWithContentsOfFile:filePath];

    NSData *signData = [RSAcryptor sianWithData:data secKeyRef:privateKeyRef];
    NSAssert([RSAcryptor verifyWithData:data signature:signData secKeyRef:publicKeyRef],@"验签失败");
//    NSData *plainData = [data subdataWithRange:NSMakeRange(0, data.length-256)];
//    NSData *signatureData = [data subdataWithRange:NSMakeRange(data.length-256, 256)];
//    NSAssert([RSAHandleer verifyWithData:plainData signature:signatureData secKeyRef:publicKeyRef], @"签名失败");
    

    
    NSData *crptyData = [RSAcryptor encryptData:[@"phbtttttt@gmail.com" dataUsingEncoding:NSUTF8StringEncoding] withKeyRef:publicKeyRef];
    NSLog(@"crptyData = %@",crptyData);
    NSData *decryptData = [RSAcryptor decryptData:crptyData withKeyRef:privateKeyRef];
    NSLog(@"decryptData = %@", decryptData);
    NSLog(@"decryptString = %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);
    
    
}

@end
