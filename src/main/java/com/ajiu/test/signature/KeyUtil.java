package com.ajiu.test.signature;

import com.ajiu.test.base64.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * description: 获取不同非对称加密算法的公私钥
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class KeyUtil {
    // 提供的密钥的内容，示例：
//    private static final String publicStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrCxhMy1Ey6tq1+vGJyA2bPnmXWmJEpk3qCmECMFk1GNtGuB1b0JBc3cdjUH7fZTMUayjasld5Od2PYqMSO0RpXQnL9z6+YbRGv6WIT8q1xb7BaFKvsqj6k2fyOIu7RLZtJiGewdBLcBe5KmxmAUzBj/1KEWsPDgmLuGBgcJKR8QIDAQAB";
//    private static final String privateStr = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKsLGEzLUTLq2rX68YnIDZs+eZdaYkSmTeoKYQIwWTUY20a4HVvQkFzdx2NQft9lMxRrKNqyV3k53Y9ioxI7RGldCcv3Pr5htEa/pYhPyrXFvsFoUq+yqPqTZ/I4i7tEtm0mIZ7B0EtwF7kqbGYBTMGP/UoRaw8OCYu4YGBwkpHxAgMBAAECgYAFe7ySsa3vuPG8Bch6h0xQXsddH8uoscArsZt8i3pApoRZFwvx5pTKNV3wBCOdG8xwaiMMJ82AGGfO8fWSXw4JWUCmiJqooIysiikyQ6gmX01DB9NZQrx0Cu8sK4qhR02Aw6kW1VZfJTcyCciGnjMZPodlQtaMvR46ENWvkjkDsQJBANtroqxrmBB18Xj1t8EvLHg6JchkFTLqPAgH99B5D43AKy7Q9m4Jf9Z96t5zxajnD/4hWAC6c88uMJ+1XUViUaUCQQDHjtWspPELgq2il2S9lwZDNKLNlA+VWMkZDnMxBcblC/Av3quv3iGNX+XQ1lapVofSXCdn1VV3w3OUfpxXWPVdAkAXKWeEl973bdvNjvKUu+wPzOOMIbRzKXKozl6EbSMNLYnhaUF6IBqUg7o1PTdSOwHfK5nkicoLxq5vTW/JETXZAkEAvgJJf645eW0+6P5fxImFQ/5dOYNN5zT3nWz9z2Khw7s/QkUxki3eIp950gQT1f73KhvmxV4CmBs49N4s/JpOXQJBAII5mtlsDg/SSQITvHKP6GCJfkMxtTdHY/RFHBKgsn7IXqsnsU00veASLmBwdeMRJJiLCKvoJQi9xvaERzBAW4o=";

    /**
     * Description: 根据提供的非加密算法名称和密钥的内容获取该非对称加密算法的公钥
     * @author: JiuDongDong
     * @param algorithm 提供的算法名称
     * @param strKeyContent  提供的密钥的内容
     * @return java.security.PublicKey 公钥
     * date: 2018/7/21 17:42
     */
    public static PublicKey getPublicKey(String algorithm, String strKeyContent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);// 根据算法名称获取该算法的密钥工厂
            // 使用密钥工厂对象生成公钥
            KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.base64DecodeWithoutPassword(strKeyContent));// 密钥规则对象(公钥的)，公钥的只能用X509EncodedKeySpec类的实例
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);// 使用密钥工厂对象 和 密钥规则对象 生成公钥
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 根据提供的非加密算法名称和密钥的内容获取该非对称加密算法的私钥
     * @author: JiuDongDong
     * @param algorithm 提供的算法名称
     * @param strKeyContent  提供的密钥的内容
     * @return java.security.PrivateKey 私钥
     * date: 2018/7/21 17:43
     */
    public static PrivateKey getPrivateKey(String algorithm, String strKeyContent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);// 根据算法名称获取该算法的密钥工厂
            // 使用密钥工厂对象生成私钥
            KeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.base64DecodeWithoutPassword(strKeyContent));// 密钥规则对象(私钥的)，私钥的只能用PKCS8EncodedKeySpec类的实例
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);// 使用密钥工厂对象 和 密钥规则对象 生成私钥
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
