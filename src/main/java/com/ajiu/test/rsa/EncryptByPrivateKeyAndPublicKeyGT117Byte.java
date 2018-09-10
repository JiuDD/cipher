package com.ajiu.test.rsa;

import com.ajiu.test.base64.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * description: 使用公钥和私钥进行非对称加密（分段加密，不区分明文长度）
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class EncryptByPrivateKeyAndPublicKeyGT117Byte {
    private static final String ENCRYPT_METHOD = "RSA";// RSA加密算法
    private static final int ENCRYPT_MAX_SIZE = 117;// 分段加密，doFinal方法每次加密字节最大长度117字节

    /**
     * Description: 使用私钥privateKey加密（分段加密，不区分明文长度）
     * @author: jiudongdong
     * @param privateKey  私钥
     * @param inputText  不区分明文长度
     * @return java.lang.String  使用私钥加密后的密文
     * date: 2018/7/21 12:05
     */
    public static String encryptByPrivateKey(PrivateKey privateKey, String inputText) {
        String resultBytes = null;// 使用私钥加密后的密文
        // 以下是使用私钥进行非对称加密过程（分段加密，不区分明文长度）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用私钥privateKey对算法对象进行初始化，初始化模式为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // 分段加密
            int offset = 0;// 偏移量
            byte[] buffer = new byte[1024];// 用于缓冲分段多次加密的密文
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (inputText.getBytes().length - offset > 0) {
                if (inputText.getBytes().length - offset >= ENCRYPT_MAX_SIZE) {
                    // 首先加密完整的117字节长度
                    buffer = cipher.doFinal(inputText.getBytes(), offset, ENCRYPT_MAX_SIZE);
                    // 重新定位偏移量
                    offset += ENCRYPT_MAX_SIZE;
                } else {
                    // 如果剩下的字节长度小于117字节，则把剩下的一次性加密完
                    buffer = cipher.doFinal(inputText.getBytes(), offset, inputText.getBytes().length - offset);
                    offset = inputText.getBytes().length;
                }
                baos.write(buffer);
            }
            // 将人类看不懂的密文进行Base64编码
            resultBytes = Base64.base64Encode(baos.toByteArray());
            return resultBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 使用公钥publicKey加密（分段加密，不区分明文长度）
     * @author: jiudongdong
     * @param publicKey  私钥
     * @param inputText  不区分明文长度
     * @return java.lang.String  使用私钥加密后的密文
     * date: 2018/7/21 12:05
     */
    public static String encryptBypublicKey(PublicKey publicKey, String inputText) {
        String resultBytes = null;// 使用私钥加密后的密文
        // 以下是使用私钥进行非对称加密过程（分段加密，不区分明文长度）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用私钥publicKey对算法对象进行初始化，初始化模式为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 分段加密
            int offset = 0;// 偏移量
            byte[] buffer = new byte[1024];// 用于缓冲分段多次加密的密文
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (inputText.getBytes().length - offset > 0) {
                if (inputText.getBytes().length - offset >= ENCRYPT_MAX_SIZE) {
                    // 首先加密完整的117字节长度
                    buffer = cipher.doFinal(inputText.getBytes(), offset, ENCRYPT_MAX_SIZE);
                    // 重新定位偏移量
                    offset += ENCRYPT_MAX_SIZE;
                } else {
                    // 如果剩下的字节长度小于117字节，则把剩下的一次性加密完
                    buffer = cipher.doFinal(inputText.getBytes(), offset, inputText.getBytes().length - offset);
                    offset = inputText.getBytes().length;
                }
                baos.write(buffer);
            }
            // 将人类看不懂的密文进行Base64编码
            resultBytes = Base64.base64Encode(baos.toByteArray());
            return resultBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        // 使用私钥进行分段加密
        String s1 = encryptByPrivateKey(KeyPairGenerate.getKeyPair().getPrivate(), "明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文");
        System.out.println("使用私钥进行分段加密：" + s1);
        // 使用公钥进行分段加密
        String s2 = encryptBypublicKey(KeyPairGenerate.getKeyPair().getPublic(), "明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文");
        System.out.println("使用公钥进行分段加密：" + s2);

    }
}
