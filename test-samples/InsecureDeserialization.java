package com.example.vulnerable;

import java.io.*;

/**
 * VULNERABLE CODE - Insecure Deserialization
 * DO NOT USE IN PRODUCTION!
 */
public class InsecureDeserialization {
    
    // CRITICAL: Deserializing untrusted data
    public Object deserializeUserData(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Can execute arbitrary code!
    }
    
    // CRITICAL: Reading serialized object from network
    public Object readFromSocket(InputStream inputStream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        return ois.readObject(); // Remote code execution risk
    }
    
    // HIGH: Deserializing from file without validation
    public Object loadConfig(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object config = ois.readObject();
        return config;
    }
    
    // CRITICAL: Using readUnshared without validation
    public void processUserObject(ObjectInputStream ois) throws Exception {
        Object obj = ois.readUnshared();
        // No type checking or validation
    }
    
    // HIGH: XMLDecoder vulnerability
    public Object decodeXML(InputStream xmlInput) {
        java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(xmlInput);
        return decoder.readObject(); // Can execute arbitrary Java code
    }
}
