package com.github.springsecurity.auth;

import com.github.springsecurity.config.JwtService;
import com.github.springsecurity.repository.UserRepository;
import com.github.springsecurity.user.Role;
import com.github.springsecurity.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        User userSaved = userRepository.save(
                User.builder()
                        .firstName(request.getFirstName())
                        .lastName(request.getLastName())
                        .email(request.getEmail())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .role(Role.USER)
                    .build()
        );
        return AuthenticationResponse.builder().token(jwtService.generateToken(userSaved)).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        User userFound = userRepository.findByEmail(request.getEmail()).orElseThrow();
        return AuthenticationResponse.builder().token(jwtService.generateToken(userFound)).build();
    }
}
