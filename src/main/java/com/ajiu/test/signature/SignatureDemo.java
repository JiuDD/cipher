package com.ajiu.test.signature;

import com.ajiu.test.base64.Base64;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * description: 数字签名
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class SignatureDemo {
    private static final String SHA256withRSA = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static final String publicStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrCxhMy1Ey6tq1+vGJyA2bPnmXWmJEpk3qCmECMFk1GNtGuB1b0JBc3cdjUH7fZTMUayjasld5Od2PYqMSO0RpXQnL9z6+YbRGv6WIT8q1xb7BaFKvsqj6k2fyOIu7RLZtJiGewdBLcBe5KmxmAUzBj/1KEWsPDgmLuGBgcJKR8QIDAQAB";
    private static final String privateStr = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKsLGEzLUTLq2rX68YnIDZs+eZdaYkSmTeoKYQIwWTUY20a4HVvQkFzdx2NQft9lMxRrKNqyV3k53Y9ioxI7RGldCcv3Pr5htEa/pYhPyrXFvsFoUq+yqPqTZ/I4i7tEtm0mIZ7B0EtwF7kqbGYBTMGP/UoRaw8OCYu4YGBwkpHxAgMBAAECgYAFe7ySsa3vuPG8Bch6h0xQXsddH8uoscArsZt8i3pApoRZFwvx5pTKNV3wBCOdG8xwaiMMJ82AGGfO8fWSXw4JWUCmiJqooIysiikyQ6gmX01DB9NZQrx0Cu8sK4qhR02Aw6kW1VZfJTcyCciGnjMZPodlQtaMvR46ENWvkjkDsQJBANtroqxrmBB18Xj1t8EvLHg6JchkFTLqPAgH99B5D43AKy7Q9m4Jf9Z96t5zxajnD/4hWAC6c88uMJ+1XUViUaUCQQDHjtWspPELgq2il2S9lwZDNKLNlA+VWMkZDnMxBcblC/Av3quv3iGNX+XQ1lapVofSXCdn1VV3w3OUfpxXWPVdAkAXKWeEl973bdvNjvKUu+wPzOOMIbRzKXKozl6EbSMNLYnhaUF6IBqUg7o1PTdSOwHfK5nkicoLxq5vTW/JETXZAkEAvgJJf645eW0+6P5fxImFQ/5dOYNN5zT3nWz9z2Khw7s/QkUxki3eIp950gQT1f73KhvmxV4CmBs49N4s/JpOXQJBAII5mtlsDg/SSQITvHKP6GCJfkMxtTdHY/RFHBKgsn7IXqsnsU00veASLmBwdeMRJJiLCKvoJQi9xvaERzBAW4o=";

    public static void main(String[] args) {
        // 加签
        String input = "我下了一个订单，订单号：201821526126";
        String sign = sign(input);
        System.out.println(sign);
        // 验签
        boolean verify = verify(input, sign);
        System.out.println("验签结果：" + verify);
    }

    /**
     * Description: 签名
     * @author: JiuDongDong
     * @param input  要签名的内容
     * @return java.lang.String 签名后的内容
     * date: 2018/7/21 17:56
     */
    public static String sign(String input) {
        // 数字签名4部曲
        try {
            // 1、创建数字签名对象
            Signature signature = Signature.getInstance(SHA256withRSA);
            // 2、初始化签名对象
            PrivateKey privateKey = KeyUtil.getPrivateKey(RSA, privateStr);
            signature.initSign(privateKey);
            // 3、传入原文
            signature.update(input.getBytes());
            // 4、开始签名
            byte[] sign = signature.sign();
            String s = Base64.base64Encode(sign);
            return s;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 验证签名
     * @author: JiuDongDong
     * @param input  待验签的密文
     * @param sign  待验签的明文
     * @return java.lang.String 签名后的内容
     * date: 2018/7/21 17:56
     */
    public static boolean verify(String input, String sign) {
        // 数字签名4部曲
        try {
            // 首先使用Base64解码
            byte[] bytes = Base64.base64DecodeWithoutPassword(input);
            // 1、创建数字签名对象
            Signature signature = Signature.getInstance(SHA256withRSA);
            // 2、初始化校验
            PublicKey publicKey = KeyUtil.getPublicKey(RSA, publicStr);
            signature.initVerify(publicKey);
            // 3、传入原文
            signature.update(input.getBytes());
            // 4、开始校验
            boolean verify = signature.verify(sign.getBytes());
            return verify;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
