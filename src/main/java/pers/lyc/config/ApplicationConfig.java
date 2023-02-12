package pers.lyc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import pers.lyc.service.UserService;

import java.util.Arrays;

@Configuration
public class ApplicationConfig {
    @Autowired
     private UserService userService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // 自动解密需要告诉Provider用什么加密算法
        daoAuthenticationProvider.setUserDetailsService(userService); // 对比信息需要告诉Provider怎么通过用户名查找数据库
        return daoAuthenticationProvider;
    }

    // 提供一个 authenticate 方法作为授权的入口，authenticate 连接到 AuthenticationProvider 进行授权
    @Bean
    @Autowired
    public AuthenticationManager authenticationManager(AuthenticationProvider authenticationProvider) throws Exception {
        // ProviderManager 是 AuthenticationManager接口的实现类
        ProviderManager providerManager = new ProviderManager(Arrays.asList(authenticationProvider));
        return providerManager;
    }
}
