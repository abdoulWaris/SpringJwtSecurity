package com.waris.jwt.security;

import com.waris.jwt.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
//@RequiredArgsConstructor
public class JwtAuthService {
private UserRepository userRepository;

private final String SECRET_KEY = "4b0e1a3f53a7e8b7eac8c5a2a0cde3e0b2f1d8a5e6c5a7b2f1e8b1c2d3f4e5a6";

    public String extractUserName(String token) {
        return extractClaims(token,Claims::getSubject);
    }
    public <T> T extractClaims(String token, Function<Claims,T>claimsResolver){
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignedKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenIsValidate(String token, UserDetails userDetails){
                final String userName = extractUserName(token);
                return (userName.equals(userDetails.getUsername()) && !isTokenIsExpired(token));
    }

    private boolean isTokenIsExpired(String token) {
                return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
                return extractClaims(token,Claims::getExpiration);
    }

    private Key getSignedKey() {
                byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
                return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(
            Map<String, Claims> extraClaims,
            UserDetails userDetails
    ){
                return Jwts
                        .builder()
                        .setClaims(extraClaims)
                        .setSubject(userDetails.getUsername())
                        .setIssuedAt(new Date(System.currentTimeMillis()))
                        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                        .signWith(getSignedKey(), SignatureAlgorithm.HS256)
                        .compact();
    }
}
