package pers.lyc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import pers.lyc.service.JwtServiceImpl;

import java.io.IOException;


// 过滤器的作用不仅是拦截，还有附加信息。比如这个过滤器就没有拦截，所有的请求都调用了doFilter方法进入下一个过滤器。
// 这个过滤器的主要作用就是为当前使用者添加一个 usernamePasswordAuthenticationToken 用于身份认证。token中包装了当前的请求request
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtServiceImpl jwtServiceImpl;

    // 处理请求首部
    private String removeBearer(String requestTokenHeader) {
        if (requestTokenHeader == null) {
            logger.warn("requestTokenHeader null");
            return null;
        }
        if (requestTokenHeader.startsWith("Bearer ")) {
            return requestTokenHeader.substring(7);
        }
        logger.warn("requestTokenHeader have not Bearer");
        return null;
    }


    private void setAuthentication(UserDetails userDetails, HttpServletRequest request) {

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), // 身份主体，通常是用户名或手机号
                userDetails.getPassword(), // 身份凭证，通常是密码或手机验证码
                userDetails.getAuthorities() // 授权信息，通常是角色 Role
        );
        // 把本次请求的HttpServletRequest也存进去。
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        // 将token添加到上下文中
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestTokenHeader = request.getHeader("Authorization"); // JWT放在首部的Authorization字段中

        String jwtToken = removeBearer(requestTokenHeader); // Jwt格式为 "Bearer 加密信息" ，获取信息时需要将前面的Bearer去除

        if (jwtServiceImpl.validateToken(jwtToken)) { // 如果token有效
            setAuthentication(jwtServiceImpl.getUserDetailFromToken(jwtToken), request); // 将匹配到的用户详情、请求设置到上下文中
        }
        filterChain.doFilter(request, response); // 不论token解析的结果如何，都通过这个过滤器，让最后一个过滤器选择拦截或通过请求

    }
}