package com.ajiu.test.rsa;

import com.ajiu.test.base64.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * description: 使用私钥解密公钥加密的密文，使用公钥解密私钥加密的密文
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class DecryptByPrivateKeyAndPublicKey {
    private static final String ENCRYPT_METHOD = "RSA";// RSA加密算法
    private static final int ENCRYPT_MAX_SIZE = 117;// 分段加密，doFinal方法每次加密字节最大长度117字节
    private static final int DECRYPT_MAX_SIZE = 128;// 分段解密，doFinal方法每次解密字节最大长度128字节

    /**
     * Description: 使用私钥privateKey解密公钥加密的密文（分段解密）
     * @author: jiudongdong
     * @param privateKey  私钥
     * @param inputText  使用公钥加密的密文
     * @return java.lang.String  使用私钥解密后的明文
     * date: 2018/7/21 13:04
     */
    public static String decryptByPrivateKey(PrivateKey privateKey, String inputText) {
        // 首先把用Base64编码的密文解码
        byte[] input = null;
        try {
            input = Base64.base64DecodeWithoutPassword(inputText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 以下是使用私钥解密过程（分段解密）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用私钥privateKey对算法对象进行初始化，初始化模式为解密模式
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // 分段解密
            int offset = 0;// 偏移量
            byte[] buffer = new byte[1024];// 用于缓冲分段多次解密的明文
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (input.length - offset > 0) {
                if (input.length - offset >= DECRYPT_MAX_SIZE) {
                    // 首先解密完整的128字节长度
                    buffer = cipher.doFinal(input, offset, DECRYPT_MAX_SIZE);
                    // 重新定位偏移量
                    offset += DECRYPT_MAX_SIZE;
                } else {
                    // 如果剩下的字节长度小于128字节，则把剩下的一次性解密完
                    buffer = cipher.doFinal(input, offset, input.length - offset);
                    offset = input.length;
                }
                baos.write(buffer);
            }
            return baos.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 使用公钥privateKey解密私钥加密的密文（分段解密）
     * @author: jiudongdong
     * @param publicKey  公钥
     * @param inputText  使用私钥加密的密文
     * @return java.lang.String  使用公钥解密后的明文
     * date: 2018/7/21 14:12
     */
    public static String decryptByPublicKey(PublicKey publicKey, String inputText) {
        // 首先把用Base64编码的密文解码
        byte[] input = null;
        try {
            input = Base64.base64DecodeWithoutPassword(inputText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 以下是使用公钥解密过程（分段解密）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用公钥publicKey对算法对象进行初始化，初始化模式为解密模式
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            // 分段解密
            int offset = 0;// 偏移量
            byte[] buffer = new byte[1024];// 用于缓冲分段多次解密的明文
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (input.length - offset > 0) {
                if (input.length - offset >= DECRYPT_MAX_SIZE) {
                    // 首先解密完整的128字节长度
                    buffer = cipher.doFinal(input, offset, DECRYPT_MAX_SIZE);
                    // 重新定位偏移量
                    offset += DECRYPT_MAX_SIZE;
                } else {
                    // 如果剩下的字节长度小于128字节，则把剩下的一次性解密完
                    buffer = cipher.doFinal(input, offset, input.length - offset);
                    offset = input.length;
                }
                baos.write(buffer);
            }
            return baos.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) {
        // 测试使用私钥解密公钥加密的密文
        // 1、首先用公钥加密一段明文，得到密文
        KeyPair keyPair = KeyPairGenerate.getKeyPair();
        String s1 = EncryptByPrivateKeyAndPublicKeyGT117Byte.encryptBypublicKey(keyPair.getPublic(), "明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文");
        // 2、使用私钥进行分段解密，得到明文
        String s2 = decryptByPrivateKey(keyPair.getPrivate(), s1);
        System.out.println(s2);


        // 测试使用公钥解密私钥加密的密文
        // 1、首先用私钥加密一段明文，得到密文
        String s3 = EncryptByPrivateKeyAndPublicKeyGT117Byte.encryptByPrivateKey(keyPair.getPrivate(), "明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文");
        // 2、使用公钥进行分段解密，得到明文
        String s4 = decryptByPublicKey(keyPair.getPublic(), s3);
        System.out.println(s4);
    }
}
