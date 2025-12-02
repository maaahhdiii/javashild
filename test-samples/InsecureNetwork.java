package com.example.vulnerable;

import java.net.*;
import javax.net.ssl.*;
import java.security.cert.*;

/**
 * VULNERABLE CODE - Insecure Network Communication
 * DO NOT USE IN PRODUCTION!
 */
public class InsecureNetwork {
    
    // CRITICAL: Accepting all SSL certificates
    public void trustAllCertificates() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAll, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // Man-in-the-middle attack possible!
    }
    
    // HIGH: Disabling hostname verification
    public void disableHostnameVerification() {
        HttpsURLConnection.setDefaultHostnameVerifier(
            new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Always trust - DANGEROUS!
                }
            }
        );
    }
    
    // CRITICAL: Using HTTP instead of HTTPS
    public String sendSensitiveData(String apiKey, String data) throws Exception {
        URL url = new URL("http://api.example.com/submit"); // Not HTTPS!
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("API-Key", apiKey); // Sent in cleartext
        return "Data sent"; // Can be intercepted
    }
    
    // HIGH: Weak TLS version
    public void useWeakTLS() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLSv1"); // Old, vulnerable
        SSLSocketFactory factory = sslContext.getSocketFactory();
        // Should use TLS 1.2 or 1.3
    }
    
    // CRITICAL: FTP with credentials in cleartext
    public void ftpUpload(String username, String password) throws Exception {
        URL url = new URL("ftp://" + username + ":" + password + "@ftp.example.com/file.txt");
        URLConnection conn = url.openConnection();
        // Credentials sent in cleartext
    }
    
    // HIGH: Socket without encryption
    public void sendData(String host, int port, String data) throws Exception {
        Socket socket = new Socket(host, port);
        socket.getOutputStream().write(data.getBytes());
        // No encryption - use SSLSocket instead
    }
}
