package com.example;

import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class OpenSSLAESEncryption {
    public static String encrypt(String data, String password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[8];
        random.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100, 256);  // Create key and IV from password and salt
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = cipher.doFinal(data.getBytes("UTF-8"));

        byte[] saltedCipher = new byte[salt.length + cipherText.length + "Salted__".length()];
        System.arraycopy("Salted__".getBytes(), 0, saltedCipher, 0, "Salted__".length());
        System.arraycopy(salt, 0, saltedCipher, "Salted__".length(), salt.length);
        System.arraycopy(cipherText, 0, saltedCipher, "Salted__".length() + salt.length, cipherText.length);

        return Base64.getEncoder().encodeToString(saltedCipher);
    }

    public static void main(String[] args) throws Exception {
        String toBeEncrypted = "AMOUNT=10&TID=#19:23&CURRENCY=EUR&LANGUAGE=DE&SUCCESS_URL=http://some.url/success&ERROR_URL=http://some.url/error&CONFIRMATION_URL=http://some.url/confirm&NAME=customer full name";
        String password = "passPhrase";
        String encryptedData = encrypt(toBeEncrypted, password);
        System.out.println("Encrypted Data: " + encryptedData);
    }
}
