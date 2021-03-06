package com.fpliu.newton.security;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 生成信息摘要的工具类
 *
 * @author 792793182@qq.com 2014-09-28
 */
public final class FingerPrint {

    public enum Algorithm {
        MD5,
        SHA_1,
        SHA_256
    }

    private static final int BUFF_SIZE = 4096;
    private static char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private FingerPrint() {
    }

    /* 用于文件校验 */
    public static String encode(Algorithm algorithm, File file) throws NoSuchAlgorithmException, IOException {
        MessageDigest messageDigest = MessageDigest.getInstance(getAlgorithmStr(algorithm));

        RandomAccessFile raFile = new RandomAccessFile(file, "r");

        if (raFile.length() <= 0) {
            raFile.close();
            return null;
        }

        int len;
        raFile.seek(0);

        byte[] buffer = new byte[BUFF_SIZE];

        while (true) {
            len = raFile.read(buffer);
            if (len > 0) {
                messageDigest.update(buffer, 0, len);
            } else {
                break;
            }
        }

        raFile.close();
        byte[] mdByte = messageDigest.digest();
        int mdByte_len = mdByte.length;
        char ret_str[] = new char[mdByte_len * 2];
        int k = 0;
        for (int i = 0; i < mdByte_len; i++) {
            byte byte0 = mdByte[i];
            ret_str[k++] = hexDigits[byte0 >>> 4 & 0xf];
            ret_str[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(ret_str);
    }

    public static String encode(Algorithm algorithm, String string) throws NoSuchAlgorithmException {
        byte[] strTemp = string.getBytes();
        MessageDigest messageDigest = MessageDigest.getInstance(getAlgorithmStr(algorithm));
        messageDigest.update(strTemp);
        byte[] md = messageDigest.digest();
        int j = md.length;
        char str[] = new char[j * 2];
        int k = 0;
        for (int i = 0; i < j; i++) {
            byte byte0 = md[i];
            str[k++] = hexDigits[byte0 >>> 4 & 0xf];
            str[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(str);
    }

    private static String getAlgorithmStr(Algorithm algorithm) {
        String algorithmStr;
        switch (algorithm) {
            case MD5:
                algorithmStr = "MD5";
                break;
            case SHA_1:
                algorithmStr = "SHA-1";
                break;
            case SHA_256:
                algorithmStr = "SHA-256";
                break;
            default:
                algorithmStr = "MD5";
                break;
        }
        return algorithmStr;
    }
}
