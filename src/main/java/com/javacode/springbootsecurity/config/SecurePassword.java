package com.javacode.springbootsecurity.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SecurePassword{
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String rawPassword = "codeando";
        String encodedPassword = encoder.encode(rawPassword);

        System.out.println(encodedPassword);

        String rawPassword2 = "code";
        String encodedPassword2 = encoder.encode(rawPassword2);
        System.out.println(encodedPassword2);
    }
}