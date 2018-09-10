package com.ajiu.test.des;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * description: DES对称加密、解密
 * @author: JiuDongDong
 * date: 2018/7/20.
 */
public class DesCipher {
    // 定义对称加密算法
    private static final String DES = "DES";

    /**
     * Description: 使用DES对称加密
     * @author: JiuDongDong
     * @param toEncryptText 待加密明文
     * @param password  密码
     * @return byte[] 加密后的字节数组
     * date: 2018/7/20 13:31
     */
    public static byte[] encrypt(String toEncryptText, String password) {
        byte[] encryptedContent = null;// 加密后的密文
        // 以下是加密流程
        try {
            // 获取加密算法对象（有可能获取不到，处理异常）
            Cipher desCipher = Cipher.getInstance(DES);
            // 拿到密钥工厂
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
            // 使用密钥工厂生产一个密钥对象
            KeySpec desKeySpec = new DESKeySpec(password.getBytes());// 密钥规则对象
            Key key = keyFactory.generateSecret(desKeySpec);
            // 算法初始化
            desCipher.init(Cipher.ENCRYPT_MODE, key);// 加密算法对象初始化，模式为加密模式
            // 加密
            byte[] toEncryptTextBytes = toEncryptText.getBytes();// 明文转化为字节数组
            encryptedContent = desCipher.doFinal(toEncryptTextBytes);// 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return encryptedContent;
    }

    /**
     * Description: DES解密
     * @author: JiuDongDong
     * @param encryptedBytes 加密后的字节数组
     * @param password  密码
     * @return java.lang.String 解密后的明文
     * date: 2018/7/20 13:35
     */
    public static String decrypt(byte[] encryptedBytes, String password) {
        String text = null;// 解密后的明文
        try {
            // 获取加密算法对象（有可能获取不到，处理异常）
            Cipher desCipher = Cipher.getInstance(DES);
            // 拿到密钥工厂
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
            // 使用密钥工厂生产一个密钥对象
            KeySpec desKeySpec = new DESKeySpec(password.getBytes());// 密钥规则对象
            Key key = keyFactory.generateSecret(desKeySpec);
            // 算法初始化
            desCipher.init(Cipher.DECRYPT_MODE, key);// 加密算法对象初始化，模式为加密模式
            // 解密
            byte[] bytes = desCipher.doFinal(encryptedBytes);
            text = new String(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return text;
    }

    /**
     * 加密算法的核心类：Cipher
     * 加密算法3部曲：
     *  1、创建Cipher对象
     *  2、初始化模式：加密还是解密
     *  3、进行加密、解密
     * @param args
     */
    public static void main(String[] args) {
        // 待加密明文
        String toEncryptText = "明文";
        // 对称加密使用的初始化私钥
        String password = "12345678";// DES对称加密算法要求初始化私钥最少为8位
        // 加密
        byte[] encrypt = DesCipher.encrypt(toEncryptText, password);
        System.out.println(new String(encrypt));// 打印密文

        // 将上面的密文解密
        String decrypt = DesCipher.decrypt(encrypt, password);
        System.out.println(decrypt);

    }

}
