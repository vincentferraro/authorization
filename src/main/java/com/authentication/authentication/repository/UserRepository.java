package com.authentication.authentication.repository;

import org.springframework.data.repository.CrudRepository;
import com.authentication.authentication.models.User;

public interface UserRepository extends CrudRepository<User, String>{

   User findByUsername(String username);
   
   
}
