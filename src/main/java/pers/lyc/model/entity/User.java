package pers.lyc.model.entity;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pers.lyc.model.Role;

import java.util.Collection;
import java.util.List;

@Entity
public class User implements UserDetails {

    @Id
    @GeneratedValue
    private Integer id;
    private String username;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    public User() {
    }

    public Integer getId() {
        return id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public User(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name())); // 权限集合由权限类组成，最简单的权限类只有【获取权限名字】、【获取权限ID】、【权限是否相等】的方法
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() { // 测试用，账号不过期
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { //  测试用，账号无禁用功能
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 测试用，权限不过期
        return true;
    }

    @Override
    public boolean isEnabled() { // 启动账号
        return true;
    }
}
