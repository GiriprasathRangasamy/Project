package com.example.server1.user.repository;

import java.util.List;
import java.util.Optional;

// import javax.management.Query;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.example.server1.user.User;


public interface UserRepo extends JpaRepository<User,String>{
    
    Optional<User> findByEmail(String email);

    @Query(value = "select * from recruiter where email=?1",nativeQuery = true)
    List<User>findemail1(String email);
} 
