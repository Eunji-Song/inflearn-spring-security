package com.security.inflearnsecurity.basic;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        (auth) -> auth.anyRequest().authenticated()
                )
                // or .httpBasic(Customizer.withDefaults())
                .formLogin(
                        form -> form
                                // 커스텀 제작 로그인 페이지
                                // .loginPage("/loginPage")
                                // 로그인 성공 후 이동할 페이지
                                .defaultSuccessUrl("/")
                                // 로그인 실패 후 이동할 페이지
                                .failureUrl("/login") // 실패했을때 이동하는 페이지
                                // 로그인 Form Action Url, default: /login
                                .loginProcessingUrl("/login_proc")
                                // 로그인 form input name 값, Spring security에서 기본으로 제공하는 폼을 사용하는 경우 자동으로 적용되지만 따로 제작한 폼을 사용하는 경우 input name값과 해당 값을 맞춰주어야 함
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                // 로그인 성공 후 실행될 핸들러
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        System.out.println("authentication = " + authentication.getName());
                                        response.sendRedirect("/hello"); // 이부분을 작성해주지 않는다면 loginProcessingUrl 페이지로 넘어간다.
                                    }
                                })
                                // 로그인 실해 후 실행될 핸들러
                                .failureHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        System.out.println("exception = " + exception.getMessage());
                                        response.sendRedirect("/login");
                                    }
                                })
                                .permitAll()
                );
        return http.build();
    }

}
