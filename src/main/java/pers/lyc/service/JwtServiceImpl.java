package pers.lyc.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {
    // 过期时间
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    // 生成密钥的KEY值，种子变量,随便取
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    // 生成密钥
    private Key getSignInKey() {
        // 用BASE64解码为二进制编码
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
//        使用 HMAC 算法生成密钥
        return Keys.hmacShaKeyFor(keyBytes);
    }


    // 从token中获取所有claims
    private Claims getAllClaimsFromToken(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey()) // token的密钥是什么
                .parseClaimsJws(token) // 用密钥解析token
                .getBody(); // 获取结果
    }

    // 从claims中获取指定数据
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        // 从token中获得所有Claims
        final Claims claims = getAllClaimsFromToken(token);

//         利用claimResolver解析claim.
        return claimsResolver.apply(claims);
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    // 从Token中获得过期时间，本例子中仅用于校验token是否有效
    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // 检查Token是否过期
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }


    // 从Java对象中创造Token字符串
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder() // 建筑者模式
                .setClaims(claims)  // 设置claims，后续的其他set信息均会被并自动放入claim哈希表，以便查询
                .setSubject(userDetails.getUsername()) // 将用户名作为内含信息传入
                .setIssuedAt(new Date(System.currentTimeMillis())) // 设置派发时间
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(getSignInKey(),SignatureAlgorithm.HS512) // 用HS512 + 密钥签名
                .compact(); // 将claims转化为JSON对象并加密成字符串
    }

    //    校验Token
    public Boolean validateToken(String token, UserDetails userDetails) {
//        从token中拿到用户名
        final String username = getUsernameFromToken(token);
        // 和指定的用户详情比较用户名
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}


