package com.waris.jwt.security;

import com.waris.jwt.common.Role;
import com.waris.jwt.model.User;
import com.waris.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
private final UserRepository userRepository;
private final PasswordEncoder passwordEncoder;
private final JwtAuthService jwtAuthService;
private final AuthenticationManager authenticationManager;

    public AuthenticateReponse register(RegisterRequest request) {
        var  user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Role.User)
                .build();
        userRepository.save(user);
        var jwtToken = jwtAuthService.generateToken(user);
        return AuthenticateReponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticateReponse authenticate(AuthenticateRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtAuthService.generateToken(user);
        return AuthenticateReponse.builder()
                .token(jwtToken)
                .build();
    }
}
