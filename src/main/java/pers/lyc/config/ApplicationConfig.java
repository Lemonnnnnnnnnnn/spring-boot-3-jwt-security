package pers.lyc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userService);
        return daoAuthenticationProvider;
    }

    // 提供一个 authenticate 方法作为授权的入口，authenticate 连接到 AuthenticationProvider 进行授权
    @Bean
    @Autowired
    public ProviderManager providerManager(AuthenticationProvider authenticationProvider) throws Exception {
        ProviderManager providerManager = new ProviderManager(Arrays.asList(authenticationProvider));
        return providerManager;
    }
}
