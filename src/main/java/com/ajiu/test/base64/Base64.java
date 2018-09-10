package com.ajiu.test.base64;

import com.ajiu.test.des.DesCipher;
import com.ajiu.test.util.Base64Util;

/**
 * description:
 *      Base64并不算是一种加密算法，通常用来对乱码的密文进行编码、解码，
 *      对乱码的密文编码后，可以将乱码编码为编码表里存在的字符，我们就可以看懂
 *      这些密文了（当然还是不知道啥意思，乱码密文实例：“;��*W��”，经Base64编码
 *      的密文实例：“”)
 * @author: JiuDongDong
 * date: 2018/7/20.
 */
public class Base64 {

    public static void main(String[] args) throws Exception {
        String toEncryptText =  "明文";
        String password = "12345678";
        // 1、先用DES进行对称加密，得到乱码的密文
        byte[] bytes = DesCipher.encrypt(toEncryptText, password);
        System.out.println("乱码的密文：" + new String(bytes));// 乱码的密文：;��*W��
        // 2、使用Base64编码乱码的密文
        String base64Encode = base64Encode(bytes);
        System.out.println("Base64编码后的密文：" + base64Encode);// Base64编码后的密文：EzuPxCpXj/w=
        // 3、使用Base64解码密文
        String s = base64DecodeWithPassword(base64Encode, password);
        System.out.println(s);// 结果为：明文
    }

    /**
     * Description: 使用Base64将乱码的密文编码为人类可以看懂的密文
     * @author: JiuDongDong
     * @param toEncryptText 乱码的密文
     * @return java.lang.String 用Base64编码的密文
     * date: 2018/7/20 14:42
     */
    public static String base64Encode(byte[] toEncryptText) {
        // 使用Base64将乱码的密文编码为人类可以看懂的密文
        String base64Text = Base64Util.encode(toEncryptText);
        return base64Text;
    }

    public static String base64DecodeWithPassword(String toDecodeText, String password) throws Exception {
        // 1、首先用Base64对密文解码
        byte[] decode = Base64Util.decode(toDecodeText);
        // 2、使用DES算法对乱码的密文进行解码
        String decrypt = DesCipher.decrypt(decode, password);
        return decrypt;
    }

    public static byte[] base64DecodeWithoutPassword(String toDecodeText) throws Exception {
        // 1、首先用Base64对密文解码
        byte[] decode = Base64Util.decode(toDecodeText);
        return decode;
    }


}
