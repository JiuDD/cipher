package com.ajiu.test.sm4;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * description: 国密SM4对称加解密算法。
 *  WAPI无线网络标准中使用的加密算法，是一种32轮的迭代非平衡Feistel结构的分组加密算法，其密钥长度和分组长度均为128。
 *  https://www.cnblogs.com/jichi/p/12907453.html
 * @author: DD.Jiu
 * date: 2021/9/18.
 */
public class Sm4Utils {

    private static final String ENCODING = "UTF-8";
    public static final String ALGORIGTHM_NAME = "SM4";
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS7Padding";
    public static final int DEFAULT_KEY_SIZE = 128;

    public Sm4Utils() {
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *  @Description:生成ecb暗号
     */
    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORIGTHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     *  @Description:自动生成密钥
     */
    public static byte[] generateKey() throws Exception {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORIGTHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }


    /**
     *  @Description:加密
     */
    public static String encryptEcb(String hexKey, String paramStr, String charset) throws Exception {
        String cipherText = "";
        if (null != paramStr && !"".equals(paramStr)) {
            byte[] keyData = ByteUtils.fromHexString(hexKey);
            charset = charset.trim();
            if (charset.length() <= 0) {
                charset = ENCODING;
            }
            byte[] srcData = paramStr.getBytes(charset);
            byte[] cipherArray = encrypt_Ecb_Padding(keyData, srcData);
            cipherText = ByteUtils.byteToHexString(cipherArray);
        }
        return cipherText;
    }

    /**
     *  @Description:加密模式之ecb
     */
    public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
        byte[] bs = cipher.doFinal(data);
        return bs;
    }

    /**
     *  @Description:sm4解密
     */
    public static String decryptEcb(String hexKey, String cipherText, String charset) throws Exception {
        String decryptStr = "";
        byte[] keyData = ByteUtils.fromHexString(hexKey);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] srcData = decrypt_Ecb_Padding(keyData, cipherData);
        charset = charset.trim();
        if (charset.length() <= 0) {
            charset = ENCODING;
        }
        decryptStr = new String(srcData, charset);
        return decryptStr;
    }

    /**
     *  @Description:解密
     */
    public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    /**
     *  @Description:密码校验
     */
    public static boolean verifyEcb(String hexKey,String cipherText,String paramStr) throws Exception {
        boolean flag = false;
        byte[] keyData = ByteUtils.fromHexString(hexKey);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] decryptData = decrypt_Ecb_Padding(keyData,cipherData);
        byte[] srcData = paramStr.getBytes(ENCODING);
        flag = Arrays.equals(decryptData,srcData);
        return flag;
    }

    /**
     *  @Description:测试类
     */
    public static void main(String[] args) {
        try {
            //原网页教程里的加解密
            String json = "{\"name\":\"color\",\"sex\":\"man\"}";
            // 自定义的32位16进制密钥
            String key = "cc9368581322479ebf3e79348a2757d9";
            System.out.println(key.length());
            //加密
            String cipher = Sm4Utils.encryptEcb(key, json, ENCODING);
            System.out.println(cipher);
            System.out.println(Sm4Utils.verifyEcb(key, cipher, json));
            //解密
            json = Sm4Utils.decryptEcb(key, cipher, ENCODING);
            System.out.println(json);







            //自己的   加密
            json = "{\"sum(node:node_num_cpu:sum)\":{\"data\":{\"result\":[{\"metric\":{},\"value\":[1630570817.272,\"6\"]}],\"resultType\":\"vector\"},\"status\":\"success\"},\"sum(node:pod_count:sum)\":{\"data\":{\"result\":[{\"metric\":{},\"value\":[1630570817.277,\"60\"]}],\"resultType\":\"vector\"},\"status\":\"success\"}}";
            key = ByteUtils.printHexString("1234567812345678".getBytes());
            cipher = Sm4Utils.encryptEcb(key, json, ENCODING);
            System.out.println(cipher);



            //自己的   解密
            String response = "66e4bfc4845dabe01a457f9a4cb1d8a6cd8be5c8610774f261b4eec251214f2dc6c4718d909a1663d2f002fed63c754377cc8cdcad8af4a07b92af22c8457617b8f4ab7c6c1f4ec34cb68e51dd2110b76fa9f4b2ee6c361323097dd8ec10972fede8f42a45b597ddeeaadc5d7831c0102b276b7cd2ebe6bda3dc9f3db67cfa1a6efb7e24ed22b7c6053258bed95a5743ac01d1c31a7df1f33d77fb3c2bf09c208900e894d1340fee8a25f3f1850aa7eebc1a11ecd44b78726a2f18829a33b546eaa624f968ba526c0de0564c7239c04f74b3aa039699851ce4dd7f832ab511f33bfdfb2dfa0c04b5f6f7d6315afa5c8ab6ebd8ff4bd4c16a35ceebdac43b9afbbd018e4e6f8f5bdd036afbf3a07ee48c80be0786d7ca4cac1aa5793714bd50eaa6686a292c5228024cf1f3aaa1fdfb426e213c814f31f99aca0ebba0003f26d3672b8613eabddb41bc9c72270e7fe3d429e05ecac1eb92c8f2a6ca00f5b4618db0ccb1a51456a9c8253734b4834987f362d9e4a247d0463c0461c67af7742ec216c905a8f75ad73b27fa102519a0d3772e061cbc580858f0a3a7f4374e989b5c54dadc959be9b5d2b52b28565cb5dc6bfe23be7c9221217328118a524426ef40dd2c8b2871e34e1c87359ae9016f3d4fc607afa7c672288a8887b40e8ec48858c5e8f68a2e6e8a7a9faca5022080f348323a793dd7067a81e759d4e072cae876e082442fa0dc97c7aff2da3945fdc3f01f38c73a3b78790a14b423c6c143bcd9535ec20030949fb25976724d78e2e3eb031fe130eb8b4af8395778f52fb3574d17884c3559c4fd7d06361ccbe21324b08f53d490d72f27065bb393ffb5490fa6f357d368b99781ad0470c743ed189dd7c452fd583ec18d9f372ab6d4a0d27de6822a7d5681e3e7c8d9817221bc3f7304231a4984464ef9d3a239818d01f949113bb5689927d2dd6423d878ca641318da";
            response = "9a2a1795e70adfcfd900e09ad301afd2485e1cec77818a08622e9ec503aa3dac114ec6c9626b4c71f79ed490ff8b69ff1697c8c03c79a73833f213a408ae98ac0115ae6deb8bc8c1a10c3d5081a03f0ec3f278f5411d12162210fa6ee58067ef081416c1345d4eb39b54733d8ccff0e128a71b50efd70a09615e1fb7bf42e11f781c3ac0ac7d6efe41fffd97d752ef62b8d2f000449e3a51edfc4c9a2f7b175a7781da4c853dbba547a12b10a78b57afe2224bfad1f35dc9c252134ebda7c41314e6508848d145a7575e972fbe57ec73d405aae440603f00a3004bfa965872bc871407f584e89bea82df3a5c81d57c81";
            response = "c553e4249448eda8250979e81f0488ea400261ba3d27739304636549b0d0505721c1bba85d50328c0b1da31cd0fbc1d8a435e3f7e642fef5dbc5dcfaa642fafb24fff057f48d9aad859e9961b84fe1d3c44ee4941730032bc2ba5c137c5c5b228544bb74d3a3477ba3b343d2da4c08955461565c3c9443de058eb13419b4a3373d8bc61baa5fa6d99c709f9488c062bb315f1ddb1a6513418e0a3326120e96f965f51d8e59cce86d1b51ffd438001e1db0150c363896e69d7d3ecf8961d58956246ef772beee4dcee00a4cb26f7f39e576bc295353e2802582168109f84132aa155439ce4930118ddeb786f13bb4dcfbd793376db82f9bcb1c839f0726c4bd659630241fdde84ff6cddeba3738e49589";
            key = "1234567812345678";
            String hexString = ByteUtils.printHexString(key.getBytes());
            String white = Sm4Utils.decryptEcb(hexString, response, ENCODING);
            System.out.println(white);

            /* 使用 hutool 封装好的SM4工具类加解密：方法1，不指定密钥 */
            SymmetricCrypto sm4 = SmUtil.sm4();
            //加密
            String encryptHex = sm4.encryptHex(json);
            System.out.println("加密后的密文 不指定密钥：" + encryptHex);
            //解密
            String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
            System.out.println("解密后的明文 不指定密钥：" + decryptStr);

            /* 使用 hutool 封装好的SM4工具类加解密：方法2，自定义密钥。效果，跟自己封装的Sm4Utils工具类是一样的，所以，还是使用这种方式，直接在其它项目引入jar hutool-all 即可*/
            json = "年薪100万";
            // key必须是16位
            String sm4Key = "1234567812345678";//自定义密钥
            SymmetricCrypto sm4Crypto = SmUtil.sm4(sm4Key.getBytes());
            encryptHex = sm4Crypto.encryptHex(json);//加密
            System.out.println("加密后的密文 自定义密钥：" + encryptHex);
            decryptStr = sm4Crypto.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
            System.out.println("解密后的明文 自定义密钥：" + decryptStr);



        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
