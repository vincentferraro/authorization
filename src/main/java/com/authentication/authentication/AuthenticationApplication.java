package com.authentication.authentication;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authentication.authentication.repository.UserRepository;
import com.authentication.authentication.models.User;
@SpringBootApplication
public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@Bean
	public ApplicationRunner dataLoader(UserRepository userRepo, PasswordEncoder encoder){
		return args->{
			userRepo.save(new User("habuma",encoder.encode("password"),"ROLE_ADMIN"));
			userRepo.save(new User("tacochef",encoder.encode("password"),"ROLE_ADMIN"));
			
		};
	}
}
