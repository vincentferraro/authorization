package com.authentication.authentication.models;

import jakarta.persistence.Id;
import lombok.Data;

@Data
public class User {
    
    @Id
    private String id;

    private String username;

    private String password;

    private String role;

    public User(String username, String password, String role){
        this.username = username;
        this.password = password;
        this.role = role;
    }
    
}
