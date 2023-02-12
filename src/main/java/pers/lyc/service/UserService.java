package pers.lyc.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pers.lyc.model.repository.UserRepository;


/*
 * 这里继承了security库的一些用户类，他们并没有什么黑科技，只是spring提出的一种标准。
 * 比如UserDetail只能由username和password两个属性，只能通过loadUserByUsername方法传入用户名来获取用户详情
 * */

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username);
    }
}