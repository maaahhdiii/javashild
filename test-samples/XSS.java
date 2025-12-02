package com.example.vulnerable;

import javax.servlet.http.*;
import java.io.*;

/**
 * VULNERABLE CODE - Cross-Site Scripting (XSS)
 * DO NOT USE IN PRODUCTION!
 */
public class XSS extends HttpServlet {
    
    // CRITICAL: Reflected XSS
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Welcome " + name + "</h1>"); // XSS vulnerability
        out.println("</body></html>");
        // Inject: <script>alert('XSS')</script>
    }
    
    // HIGH: Stored XSS in comment system
    public String displayComment(String userComment) {
        return "<div class='comment'>" + userComment + "</div>";
        // No sanitization - stored XSS
    }
    
    // CRITICAL: DOM-based XSS
    public String generateHTML(String searchQuery) {
        return "<script>document.getElementById('search').innerHTML = '" + 
               searchQuery + "';</script>";
        // Can inject: '; alert('XSS'); //
    }
    
    // HIGH: XSS in JSON response
    public String getJSON(String userData) {
        return "{\"message\": \"" + userData + "\"}";
        // Can break JSON: \"}); alert('XSS'); ({\"
    }
    
    // CRITICAL: XSS in error messages
    public void showError(HttpServletResponse response, String errorMsg) 
            throws IOException {
        response.getWriter().println(
            "<div class='error'>Error: " + errorMsg + "</div>"
        );
    }
    
    // HIGH: XSS in URL parameters
    public String buildRedirect(String returnUrl) {
        return "<a href='" + returnUrl + "'>Click here</a>";
        // Can inject: javascript:alert('XSS')
    }
}
