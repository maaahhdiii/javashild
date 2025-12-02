package com.security.ai.web;

import com.security.ai.web.controller.SecurityAgentController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

/**
 * Spring Boot application for AI Security Agent Web Interface
 */
@SpringBootApplication
@ComponentScan(basePackages = {"com.security.ai"})
public class SecurityAgentWebApplication {
    
    public static void main(String[] args) {
        // Set system property to ignore Java 25 class format during scanning
        System.setProperty("spring.classformat.ignore", "true");
        SpringApplication.run(SecurityAgentWebApplication.class, args);
    }
    
    /**
     * Manually register the controller as a bean to bypass class format scanning
     */
    @Bean
    public SecurityAgentController securityAgentController() {
        return new SecurityAgentController();
    }
}
