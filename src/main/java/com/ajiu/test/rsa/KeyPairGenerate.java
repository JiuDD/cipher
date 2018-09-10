package com.ajiu.test.rsa;

import com.ajiu.test.base64.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * description: 演示非对称加密的密钥对的获取、加密长度小于117字节（byte）的数据
 * @author: JiuDongDong
 * date: 2018/7/20.
 */
public class KeyPairGenerate {
    private static final String ENCRYPT_METHOD = "RSA";// RSA加密算法

    /**
     * Description: 获取默认的秘钥对
     * @author: JiuDongDong
     * @return java.security.KeyPair 秘钥对
     * date: 2018/7/21 11:29
     */
    public static KeyPair getKeyPair() {
        try {
            // 获取RSA的秘钥对获取实例
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ENCRYPT_METHOD);
            // 使用该实例获取秘钥对实例
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            System.out.println(keyPair);
            // 使用秘钥对实例生成公钥和私钥
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            // 使用Base64工具类将上面的公私钥编码为人类能看懂的公私钥字符串
            String base64EncodePrivateKey = Base64.base64Encode(privateKey.getEncoded());
            String base64EncodePublicKey = Base64.base64Encode(publicKey.getEncoded());
            System.out.println("经过base64编码的公钥：" + base64EncodePublicKey);
            System.out.println("经过base64编码的私钥：" + base64EncodePrivateKey);
            return keyPair;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


}
