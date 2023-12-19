package com.example.springsecurity.auth;


import com.example.springsecurity.auth.model.AuthenticationResponse;
import com.example.springsecurity.auth.model.AuthenticationrRequest;
import com.example.springsecurity.auth.model.RegisterRequest;
import com.example.springsecurity.config.JwtService;
import com.example.springsecurity.dao.Role;
import com.example.springsecurity.dao.User;
import com.example.springsecurity.repository.UserRepository;
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

    // 將用戶註冊請求的資訊存入數據庫，並產生一個 JwtToken, 並將其回傳
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .userName(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    // 用於已存至數據庫的用戶，此處利用 user 的 Email 去數據庫確認是否存在，同樣為其建立一個 JwtToken, 並將其回傳
    // Tips:
    // 1. authenticationManager 使用 authenticate 方法，取得 AuthenticationManagerBuilder 物件
    // 2. AuthenticationManagerBuilder 提供配置的內容，也就是指 AuthenticationConfiguration
    // 3. AuthenticationConfiguration 會建立一個 DaoAuthenticationProvider(預設)，用於處理用戶的認證方式
    public AuthenticationResponse authenticate(AuthenticationrRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(), request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
