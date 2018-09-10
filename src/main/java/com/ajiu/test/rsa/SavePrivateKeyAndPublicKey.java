package com.ajiu.test.rsa;

import com.ajiu.test.base64.Base64;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;

/**
 * description: 将公钥和私钥保存起来，目的：
 *                  之前的加密、解密、分段加密、分段解密，每次都生成了一对新的密钥对，
 *                  实际上在生产上，生成一次密钥对就行了，就像银行，生成一次就将公钥
 *                  发送给我们了，以后就不会再改变了。
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class SavePrivateKeyAndPublicKey {
    private static final String publicStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrCxhMy1Ey6tq1+vGJyA2bPnmXWmJEpk3qCmECMFk1GNtGuB1b0JBc3cdjUH7fZTMUayjasld5Od2PYqMSO0RpXQnL9z6+YbRGv6WIT8q1xb7BaFKvsqj6k2fyOIu7RLZtJiGewdBLcBe5KmxmAUzBj/1KEWsPDgmLuGBgcJKR8QIDAQAB";
    private static final String privateStr = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKsLGEzLUTLq2rX68YnIDZs+eZdaYkSmTeoKYQIwWTUY20a4HVvQkFzdx2NQft9lMxRrKNqyV3k53Y9ioxI7RGldCcv3Pr5htEa/pYhPyrXFvsFoUq+yqPqTZ/I4i7tEtm0mIZ7B0EtwF7kqbGYBTMGP/UoRaw8OCYu4YGBwkpHxAgMBAAECgYAFe7ySsa3vuPG8Bch6h0xQXsddH8uoscArsZt8i3pApoRZFwvx5pTKNV3wBCOdG8xwaiMMJ82AGGfO8fWSXw4JWUCmiJqooIysiikyQ6gmX01DB9NZQrx0Cu8sK4qhR02Aw6kW1VZfJTcyCciGnjMZPodlQtaMvR46ENWvkjkDsQJBANtroqxrmBB18Xj1t8EvLHg6JchkFTLqPAgH99B5D43AKy7Q9m4Jf9Z96t5zxajnD/4hWAC6c88uMJ+1XUViUaUCQQDHjtWspPELgq2il2S9lwZDNKLNlA+VWMkZDnMxBcblC/Av3quv3iGNX+XQ1lapVofSXCdn1VV3w3OUfpxXWPVdAkAXKWeEl973bdvNjvKUu+wPzOOMIbRzKXKozl6EbSMNLYnhaUF6IBqUg7o1PTdSOwHfK5nkicoLxq5vTW/JETXZAkEAvgJJf645eW0+6P5fxImFQ/5dOYNN5zT3nWz9z2Khw7s/QkUxki3eIp950gQT1f73KhvmxV4CmBs49N4s/JpOXQJBAII5mtlsDg/SSQITvHKP6GCJfkMxtTdHY/RFHBKgsn7IXqsnsU00veASLmBwdeMRJJiLCKvoJQi9xvaERzBAW4o=";

    /**
     * Description: 根据已知的私钥密文获取私钥
     * @author: JiuDongDong
     * @param privateStr  私钥密文
     * @return java.security.PrivateKey 私钥
     * date: 2018/7/21 14:52
     */
    public PrivateKey getPrivateKey(String privateStr) {
        try {
            // 拿到密钥工厂对象
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 使用密钥工厂对象生成私钥
            KeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.base64DecodeWithoutPassword(privateStr));// 密钥规则对象(私钥的)，私钥的只能用PKCS8EncodedKeySpec类的实例
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);// 使用密钥工厂对象 和 密钥规则对象 生成私钥
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 根据已知的公钥密文获取公钥
     * @author: JiuDongDong
     * @param publicStr 公钥密文
     * @return java.security.PublicKey 公钥
     * date: 2018/7/21 14:53
     */
    public PublicKey getPublicKey(String publicStr) {
        try {
            // 拿到密钥工厂对象
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 使用密钥工厂对象生成公钥
            KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.base64DecodeWithoutPassword(publicStr));// 密钥规则对象(公钥的)，公钥的只能用X509EncodedKeySpec类的实例
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);// 使用密钥工厂对象 和 密钥规则对象 生成公钥
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
