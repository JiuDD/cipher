package com.ajiu.test.rsa;

import com.ajiu.test.base64.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * description: 使用公钥和私钥进行非对称加密（明文长度小于等于117字节）
 * @author: JiuDongDong
 * date: 2018/7/21.
 */
public class EncryptByPrivateKeyAndPublicKeyLT117Byte {
    private static final String ENCRYPT_METHOD = "RSA";// RSA加密算法

    /**
     * Description: 使用私钥privateKey加密（本demo只演示明文长度小于等于117个byte，如果大于117个字节，需使用分段加密，见后面的demo）
     * @author: JiuDongDong
     * @param privateKey  私钥
     * @param inputText  明文长度小于等于117个byte
     * @return java.lang.String  使用私钥加密后的密文
     * date: 2018/7/21 11:23
     */
    public static String encryptByPrivateKey(PrivateKey privateKey, String inputText) {
        String s = null;// 使用私钥加密后的密文
        // 以下是使用私钥进行非对称加密过程（明文长度小于等于117字节）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用私钥privateKey对算法对象进行初始化，初始化模式为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // 加密长度小于等于117字节的明文
            byte[] bytes = cipher.doFinal(inputText.getBytes());// doFinal方法每次加密最大117字节
            // 将人类看不懂的密文进行Base64编码
            s = Base64.base64Encode(bytes);
            return s;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Description: 使用公钥publicKey加密（本demo只演示明文长度小于等于117个byte，如果大于117个字节，需使用分段加密，见后面的demo）
     * @author: JiuDongDong
     * @param publicKey  公钥
     * @param inputText  明文长度小于等于117个byte
     * @return java.lang.String  使用公钥加密后的密文
     * date: 2018/7/21 11:23
     */
    public static String encryptByPublicKey(PublicKey publicKey, String inputText) {
        String s = null;// 使用私钥加密后的密文
        // 以下是使用私钥进行非对称加密过程（明文长度小于等于117字节）
        // 获取RSA加密算法对象
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ENCRYPT_METHOD);
            // 使用私钥privateKey对算法对象进行初始化，初始化模式为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 加密长度小于等于117字节的明文
            byte[] bytes = cipher.doFinal(inputText.getBytes());// doFinal方法每次加密最大117字节
            // 将人类看不懂的密文进行Base64编码
            s = Base64.base64Encode(bytes);
            return s;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        // 测试获取默认的公私钥
        KeyPair keyPair = KeyPairGenerate.getKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();// 私钥
        PublicKey publicKey = keyPair.getPublic();// 公钥
        // 使用privateKey加密长度小于117byte的明文
        String s1 = encryptByPrivateKey(privateKey, "长度小于等于117字节的明文");
        System.out.println("base64编码的密文展示,私钥加密: " + s1);// base64编码的密文展示
        // 使用publicKey加密长度小于117byte的明文
        String s2 = encryptByPublicKey(publicKey, "长度小于等于117字节的明文");
        System.out.println("base64编码的密文展示,公钥加密: " + s2);// base64编码的密文展示


    }
}
