package com.javacode.springbootsecurity.basic;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
        .passwordEncoder(new BCryptPasswordEncoder())
            .withUser("hugo")
            .password("$2a$10$iOwoM2EAn64sOL9FTAe5wuYCOYXt5qTX6oFcw.ZElhBJFxSaalMne")
            .roles("USER") 
            
        .and()
            .withUser("jesus")
            .password("$2a$10$xos.gKEt7n5Ql6TDYX296eIqnGqWJIbsyrqsbBc6b.kKkHk.OS3Jq")
            .roles("ADMIN"); 

    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();

        
    }
}
