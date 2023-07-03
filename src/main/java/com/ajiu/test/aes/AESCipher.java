package com.ajiu.test.aes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class AESCipher {

    public static void main(String[] args) throws Exception {
        // 生成密钥 (随机生成)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        System.out.println("密钥： " + base64Key);

        // 加密
        String plainText = "这是一个待加密的文本";
        byte[] encryptedBytes = encrypt(plainText, base64Key);
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("加密后的文本： " + encryptedText);

        // 解密
        byte[] decryptedBytes = decrypt(encryptedBytes, base64Key);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("解密后的文本： " + decryptedText);
    }

    public static byte[] encrypt(String plainText, String base64Key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decrypt(byte[] encryptedBytes, String base64Key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(encryptedBytes);
    }

}

