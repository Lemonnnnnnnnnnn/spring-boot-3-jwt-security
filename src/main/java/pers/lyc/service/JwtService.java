package pers.lyc.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    // 将用户详情用密钥生成token
    String generateToken(UserDetails userDetails);

    // 从Token中获得用户名
    String getUsernameFromToken(String token);

    // 校验token
    Boolean validateToken(String token, UserDetails userDetails);
}
