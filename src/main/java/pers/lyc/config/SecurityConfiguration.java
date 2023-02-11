package pers.lyc.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()// 本例子中不处理csrf攻击
                .authorizeHttpRequests(authorize -> authorize // 配置路由和权限的关系
                        .requestMatchers("/api/v1/auth/**").permitAll() // **表示匹配所有子路由，/api/v1/auth/** 下的路由均允许直接过Filter
                        .anyRequest().authenticated() // 其他所有路由都需要登录后才能访问，这里的authenticated()表示已经进行过了身份验证Authentication
                )
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 将session策略设为无状态策略，不会保存Session状态
                .and() // 用一个and方法返回HttpSecurity对象，这样就可以继续链式调用了
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class); // 表示在默认的【用户名密码身份认证过滤器】之前插入Jwt过滤器
        return http.build();
    }

}

