package com.ajiu.test.aes;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;

/**
 * description: AES 用法，全部使用 HuTool的工具类
 * @author: DD.Jiu
 * date: 2022/1/13.
 */
public class AESDemo {

    public static void main(String[] args) {
        String content = "test中文";

        /******************************************  不使用密钥，通常不采用    ***********************************/
        AES aes1 = SecureUtil.aes();    //不使用密钥，通常不采用
        //普通加密
        byte[] encrypt1 = aes1.encrypt(content);
        System.out.println("普通加密 后：" + new String(encrypt1));
        //普通解密
        byte[] decrypt1 = aes1.decrypt(encrypt1);
        System.out.println("普通解密 后：" + new String(decrypt1));
        System.out.println("-----------------------------------------");
        /******************************************  不使用密钥，通常不采用    ***********************************/


        /******************************************  使用指定密钥   ***********************************/
        //随机生成密钥
        byte[] key2 = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
        //构建
        AES aes2 = SecureUtil.aes(key2);
        //加密
        byte[] encrypt2 = aes2.encrypt(content);
        System.out.println("使用指定密钥加密 后：" + new String(encrypt2));
        //解密
        byte[] decrypt2 = aes2.decrypt(encrypt2);
        System.out.println("使用指定密钥解密 后：" + new String(decrypt2));
        System.out.println("-----------------------------------------");
        /******************************************  使用指定密钥   ***********************************/


        /******************************************  加密为16进制   ***********************************/
        //加密为16进制表示
        String encryptHex = aes2.encryptHex(content);
        System.out.println("加密为16进制 后: " + encryptHex);
        //解密为原字符串
        String decryptStr = aes2.decryptStr(encryptHex);
        System.out.println("16进制密文解密 后：" + decryptStr);
        System.out.println("-----------------------------------------");
        /******************************************  加密为16进制   ***********************************/


        /******************************************  加密为Base64   ***********************************/
        //加密为16进制表示
        String base64 = aes2.encryptBase64(content);
        System.out.println("加密为 Base64 后: " + base64);
        //解密为原字符串
        String decryptStr1 = aes2.decryptStr(base64);
        System.out.println("Base64密文解密 后：" + decryptStr1);
        /******************************************  加密为16进制   ***********************************/









    }
}
