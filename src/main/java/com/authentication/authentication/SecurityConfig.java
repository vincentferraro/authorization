package com.authentication.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.authentication.authentication.repository.UserRepository;

@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)throws Exception{
        return http.authorizeHttpRequests(
                authorizeRequests->
                authorizeRequests.anyRequest()
                .authenticated()).formLogin().and().build();

    }

    @Bean
    UserDetailsService userDetailsService(UserRepository userRepo){
        return username->userRepo.findByUsername(username);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
