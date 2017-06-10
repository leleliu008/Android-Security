package com.fpliu.newton.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 对称加密和解密
 *
 * @author 792793182@qq.com 2014-09-28
 */
public final class SymmetricalEncryption {

    private SymmetricalEncryption() {
    }

    /**
     * 加密
     *
     * @param algorithms 算法
     * @param input      要加密的数据
     * @param key        密钥
     * @return 加密后的数据
     */
    public static byte[] encrypt(Algorithm algorithms, byte[] input, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return crypt(Cipher.ENCRYPT_MODE, algorithms, input, key);
    }

    /**
     * 解密
     *
     * @param algorithms 算法
     * @param input      要解密的数据
     * @param key        密钥
     * @return 解密后的数据
     */
    public static byte[] decrypt(Algorithm algorithms, byte[] input, byte[] key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return crypt(Cipher.DECRYPT_MODE, algorithms, input, key);
    }

    private static byte[] crypt(int opMode, Algorithm algorithms, byte[] input, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (key == null || key.length == 0) {
            return null;
        }

        String algorithmsStr = "";

        switch (algorithms) {
            case DES:
                algorithmsStr = "DES/ECB/PKCS7Padding";
                break;
            case DES3:
                algorithmsStr = "DESede/ECB/PKCS5Padding";
                break;
            case AES:
                algorithmsStr = "AES/ECB/PKCS7Padding";
                break;
            default:
                break;
        }

        SecretKey desKey = new SecretKeySpec(key, algorithmsStr);
        Cipher cipher = Cipher.getInstance(algorithmsStr);
        cipher.init(opMode, desKey);
        return cipher.doFinal(input);
    }

    public enum Algorithm {
        DES, //传入的key必须是8byte=64bit
        DES3,//传入的key必须是128bit=16byte、192bit=24byte
        AES  //传入的key必须是128bit=16byte、192bit=24byte、256bit=32byte
    }
}
