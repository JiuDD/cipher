package com.ajiu.test.des;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.DES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;

/**
 * description: DES 用法，全部使用 HuTool的工具类
 *  DES 的用法，跟 AES 几乎一致
 * @author: DD.Jiu
 * date: 2022/1/13.
 */
public class DESDemo {

    public static void main(String[] args) {
        String content = "test中文";

        /******************************************  不使用密钥，通常不采用    ***********************************/
        DES des1 = SecureUtil.des();    //不使用密钥，通常不采用
        //普通加密
        byte[] encrypt1 = des1.encrypt(content);
        System.out.println("普通加密 后：" + new String(encrypt1));
        //普通解密
        byte[] decrypt1 = des1.decrypt(encrypt1);
        System.out.println("普通解密 后：" + new String(decrypt1));
        System.out.println("-----------------------------------------");
        /******************************************  不使用密钥，通常不采用    ***********************************/

        /******************************************  使用指定密钥   ***********************************/
        //随机生成密钥
        byte[] key2 = SecureUtil.generateKey(SymmetricAlgorithm.DES.getValue()).getEncoded();
        //如果指定密钥 123456，则：***********************************************************************
        //key2 = "123456".getBytes();

        //构建
        DES des2 = SecureUtil.des(key2);
        //加密
        byte[] encrypt2 = des2.encrypt(content);
        System.out.println("使用指定密钥加密 后：" + new String(encrypt2));
        //解密
        byte[] decrypt2 = des2.decrypt(encrypt2);
        System.out.println("使用指定密钥解密 后：" + new String(decrypt2));
        System.out.println("-----------------------------------------");
        /******************************************  使用指定密钥   ***********************************/



        /******************************************  加密为16进制   ***********************************/
        //加密为16进制表示
        String encryptHex = des2.encryptHex(content);
        System.out.println("加密为16进制 后: " + encryptHex);
        //解密为原字符串
        String decryptStr = des2.decryptStr(encryptHex);
        System.out.println("16进制密文解密 后：" + decryptStr);
        System.out.println("-----------------------------------------");
        /******************************************  加密为16进制   ***********************************/


        /******************************************  加密为Base64   ***********************************/
        //加密为16进制表示
        String base64 = des2.encryptBase64(content);
        System.out.println("加密为 Base64 后: " + base64);
        //解密为原字符串
        String decryptStr1 = des2.decryptStr(base64);
        System.out.println("Base64密文解密 后：" + decryptStr1);
        /******************************************  加密为16进制   ***********************************/









    }
}
