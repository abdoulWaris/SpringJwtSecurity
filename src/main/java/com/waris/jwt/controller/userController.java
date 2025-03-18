package com.waris.jwt.controller;

import com.waris.jwt.security.AuthService;
import com.waris.jwt.security.AuthenticateReponse;
import com.waris.jwt.security.AuthenticateRequest;
import com.waris.jwt.security.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class userController {
    private final AuthService service;
    @PostMapping("/register")
    public ResponseEntity<AuthenticateReponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateReponse> register(
            @RequestBody AuthenticateRequest request
    ){
        return ResponseEntity.ok(service.authenticate(request));
    }
}
