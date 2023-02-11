package pers.lyc.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pers.lyc.model.Role;
import pers.lyc.model.dao.AuthenticationResponse;
import pers.lyc.model.dao.LoginRequest;
import pers.lyc.model.dao.RegisterRequest;
import pers.lyc.model.entity.User;
import pers.lyc.model.repository.UserRepository;

@Service

public class AuthenticationService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtServiceImpl jwtServiceImpl;

    @Autowired
    private ProviderManager providerManager;

    @Autowired
    private UserRepository userRepository;

    private UserService userService;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = new User(
                request.getUsername(),
                passwordEncoder.encode(request.getPassword()), // 存入数据库之前先加密
                Role.USER
        );
        userRepository.save(user);
        String jwtToken = jwtServiceImpl.generateToken(user);
        return new AuthenticationResponse(jwtToken);
    }

    public AuthenticationResponse authenticate(LoginRequest request) {
        // 匹配传入的用户名、密码
        // authenticationManager -> ProviderManager  -> AbstractUserDetailsAuthenticationProvider -> DaoAuthenticationProvider ->
        // DaoAuthenticationProvider.getUserDetailService.loadUserByUsername(username) ->
        // DaoAuthenticationProvider.additionalAuthenticationChecks().passwordEncoder.matches(password)
        Authentication authentication = providerManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // authenticationManager.authenticate 并没有设置SecurityContextHolder.getContext()，因此下面返回实体的是通过request.permitAll()的一个匿名用户"anonymousUser"
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        User user = (User) authentication.getPrincipal();
        // 生成token
        String jwtToken = jwtServiceImpl.generateToken(user);
        // 返回token
        return new AuthenticationResponse(jwtToken);
    }
}
