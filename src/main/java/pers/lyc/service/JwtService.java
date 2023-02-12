package pers.lyc.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    // 将用户详情用密钥生成token
    String generateToken(UserDetails userDetails);

    UserDetails getUserDetailFromToken(String token);

    // 校验token
    Boolean validateToken(String token);
}
