package com.ajiu.test.sm4;

/**
 * description: 16进制、byte[]、String 互相转换
 * https://www.cnblogs.com/pwenlee/p/4779039.html
 * @author: DD.Jiu
 * date: 2021/9/18.
 */
public class ByteUtils {


    /**
     * Description: HexString——>byte
     * @author: JiuDD
     * @param hexString
     * @return byte[]
     * date: 2021/9/18 15:51
     */
    public static byte[] fromHexString(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }



    /**
     * Description: byte——>String
     * @author: JiuDD
     * @param src
     * @return java.lang.String
     * date: 2021/9/18 15:52
     */
    public static String byteToHexString(byte[] src){
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    /**
     * Description: byte——>hexString
     *  可以将项目中给的明文密码，转换成16进制。SM4需要16进制
     * @author: JiuDD
     * @return java.lang.String
     * date: 2021/9/18 15:53
     */
    public static String printHexString(byte[] b) {
        String a = "";
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            a = a+hex;
        }
        return a;
    }
}
