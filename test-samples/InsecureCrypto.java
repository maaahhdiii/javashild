package com.example.vulnerable;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * VULNERABLE CODE - Insecure Cryptography
 * DO NOT USE IN PRODUCTION!
 */
public class InsecureCrypto {
    
    // CRITICAL: Using DES (broken encryption)
    public byte[] encryptDES(byte[] data, String password) throws Exception {
        SecretKeySpec key = new SecretKeySpec(password.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
        // DES is cryptographically broken
    }
    
    // HIGH: ECB mode (insecure)
    public byte[] encryptECB(byte[] data) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
        // ECB mode reveals patterns
    }
    
    // CRITICAL: Weak random number generator
    public String generateToken() {
        java.util.Random random = new java.util.Random();
        return String.valueOf(random.nextInt());
        // Predictable - not cryptographically secure
    }
    
    // HIGH: MD5 hash (broken)
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
        // MD5 is broken - use bcrypt/argon2
    }
    
    // CRITICAL: No salt in password hash
    public String hashWithoutSalt(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new String(md.digest(password.getBytes()));
        // Rainbow table attack possible
    }
    
    // HIGH: Small RSA key
    public KeyPair generateWeakRSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512); // Too small - should be 2048+
        return keyGen.generateKeyPair();
    }
    
    // CRITICAL: Static IV (Initialization Vector)
    public byte[] encryptWithStaticIV(byte[] data) throws Exception {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        byte[] iv = new byte[16]; // All zeros - predictable!
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }
}
