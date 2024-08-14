package com.example.server1.auth;

import com.example.server1.user.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String name;
    private String company;
    private long mobile;
    private String email;
    private String password;
    private Role role;
   
}
