package com.example.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {   // 用於生成、解析和驗證JWT

    private static final String SECRET_KEY = "4A404E635266556A586E3272357538782F413F442A472D4B6150645367566B59";


    // 從 JwtToken 中解析出儲存的用戶名 (= getUsernameFromToken)
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    // 根據名稱從 JwtToken 中的 Claim 中獲取值
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllChaims(token);
        return claimsResolver.apply(claims);
    }

    // 返回 JwtToken 中的所有 Claims
    private Claims extractAllChaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 用於生成一個新的 JwtToken, 並將用戶信息存儲在其中
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 用於驗證 JwtToken 的有效性，並檢查其中存儲的用戶信息是否與提供的用戶信息匹配。
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenValid(token);
    }

    // 僅驗證 JwtToken 的有效性，而不檢查其中存儲的用戶信息。
    private boolean isTokenValid(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 從 JwtToken 中解析出過期時間 (= getExpirationDateFromToken)
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Key getSignInKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
