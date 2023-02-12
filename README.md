# Spring Boot 3.0 + Spring-Security 6.0 的 JWT 实现

原文：https://github.com/ali-bouali/spring-boot-3-jwt-security

## 新增
添加中文注释。

## 更改

- 数据库改为mysql
- 利用docker-compose生成mysql环境
- 简化Filter等地方的代码

## 特性
- 用户使用JWT方式进行注册和登录认证
- 密码用 BCrypt 加密
- 用 Spring Secure 进行基于Role的身份认证。

## 技术栈
* Spring Boot 3.0
* Spring Security
* JSON Web Tokens (JWT)
* BCrypt
* Maven

## Getting Started

**环境:**

* JDK 17+
* Maven 3+


**本地运行:**
1. docker-compose up ：使用docker-compose初始化数据库。 
2.  mvn spring-boot:run : 启动项目

-> 项目运行在： http://localhost:8080。本项目无前端，使用postman等请求模拟器使用。
