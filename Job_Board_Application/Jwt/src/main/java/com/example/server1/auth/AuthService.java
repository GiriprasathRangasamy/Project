package com.example.server1.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.server1.config.JwtService;
import com.example.server1.user.User;
import com.example.server1.user.repository.UserRepo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .name(registerRequest.getName())
                .company(registerRequest.getCompany())
                .mobile(registerRequest.getMobile())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();

        var savedUser = userRepo.save(user);

        String jwtToken = jwtService.generateToken(savedUser);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .alert("Registration successful")
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            // Check if the user exists
            var user = userRepo.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // If the user exists, validate the credentials and authenticate the user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // If authentication is successful, generate the JWT token
            String jwtToken = jwtService.generateToken(user);

            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .alert("Login successful")
                    .build();

        } catch (UsernameNotFoundException e) {
            return AuthenticationResponse.builder()
                    .alert("User not found")
                    .build();
        } catch (BadCredentialsException e) {
            return AuthenticationResponse.builder()
                    .alert("Incorrect password")
                    .build();
        } catch (Exception e) {
            return AuthenticationResponse.builder()
                    .alert("Authentication failed")
                    .build();
        }
    }
}
