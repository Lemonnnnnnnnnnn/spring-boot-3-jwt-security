package pers.lyc.config;

import io.jsonwebtoken.ExpiredJwtException;
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
import pers.lyc.service.UserService;

import java.io.IOException;


// 过滤器的作用不仅是拦截，还有附加信息。比如这个过滤器就没有拦截，所有的请求都调用了doFilter方法进入下一个过滤器。
// 这个过滤器的主要作用就是为当前使用者添加一个 usernamePasswordAuthenticationToken 用于身份认证。token中包装了当前的请求request
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    UserService userService;

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

    // 从token中拿到用户信息
    private String getUsername(String jwtToken) {
        String username = null;
        try {
            username = jwtServiceImpl.getUsernameFromToken(jwtToken); // 从token内含信息中拿到username
        } catch (IllegalArgumentException e) {
            logger.warn("Unable to get JWT Token");
        } catch (ExpiredJwtException e) {
            logger.warn("JWT Token has expired");
        }
        return username;
    }

    // 将带有用户名、密码存储进 context 中（即对该用户进行授权），这样做有两个目的：
    // 1. 在到达最后一个过滤器 FilterSecurityInterceptor 时，根据http的配置从 SecurityContextHolder中获取 Authentication，比对用户拥有的权限和所访问资源需要的权限。
    // 2. 到达 controller 时可以直接从 context 中取用户数据
    private void setAuthentication(UserDetails userDetails, HttpServletRequest request) {

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), // 身份主体，通常是用户名或手机号
                userDetails.getPassword(), // 身份凭证，通常是密码或手机验证码
                userDetails.getAuthorities() // 授权信息，通常是角色 Role
        );
        // 源码：
//        public UsernamePasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
//        super(authorities);
//        this.principal = principal;
//        this.credentials = credentials;
//        super.setAuthenticated(true); // 表示已授权，如果对http请求配置了 .anyRequest().authenticated() ，则通过一个getAuthentication 的方法获取这个值
//    }

        // 把本次请求的HttpServletRequest也存进去。
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // 在这里将本次请求用户的信息储存到 ThreadLocal 中.
        // 这样到达controller时就可以直接通过SecurityContextHolder.getContext().getAuthentication()来直接获得用户信息，而不用再次请求数据库
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestTokenHeader = request.getHeader("Authorization");

        String jwtToken = removeBearer(requestTokenHeader);

//        // 状态：无token
        if (jwtToken == null) {
            logger.warn("JWT Token does not begin with Bearer String");
            filterChain.doFilter(request, response);
            return;
        }


        // 状态：token过期或token解析失败
        String username = getUsername(jwtToken);
        if (username == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 状态：已登录，token解析成功：校验token和数据库信息，若一致，将信息存入上下文context中
        // 查询数据库
        UserDetails userDetails = userService.loadUserByUsername(username);
        // 比对token内含信息和查询到的用户信息
        //
        if (!jwtServiceImpl.validateToken(jwtToken, userDetails)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 身份认证
        setAuthentication(userDetails, request);
        filterChain.doFilter(request, response);
    }
}