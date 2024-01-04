package com.security.inflearnsecurity.basic;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 페이지 인증 - 모든 페이지에 대하여 인증 요구
        http.authorizeHttpRequests((auth) -> auth.anyRequest().authenticated());

        // 로그인 - http basic
        // http.httpBasic(Customizer.withDefaults());

        // 로그인 - formLogin
        http.formLogin(
            form -> form
                    // .loginPage("/loginPage")
                    .defaultSuccessUrl("/") // 로그인 성공 후 이동할 페이지
                    .failureUrl("/login") // 로그인 실패 후 이동할 페이지
                    .loginProcessingUrl("/login_proc") // 로그인 Form Action Url, default: /login
                    // 로그인 form input name 값, Spring security에서 기본으로 제공하는 폼을 사용하는 경우 자동으로 적용되지만 따로 제작한 폼을 사용하는 경우 input name값과 해당 값을 맞춰주어야 함
                    .usernameParameter("userId")
                    .passwordParameter("passwd")
                    // 로그인 성공 핸들러
                    .successHandler(new AuthenticationSuccessHandler() {
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            System.out.println("authentication = " + authentication.getName());
                            response.sendRedirect("/hello"); // 이부분을 작성해주지 않는다면 loginProcessingUrl 페이지로 넘어간다.
                        }
                    })
                    // 로그인 실패 핸들러
                    .failureHandler(new AuthenticationFailureHandler() {
                        @Override
                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                            System.out.println("exception = " + exception.getMessage());
                            response.sendRedirect("/login");
                        }
                    })
                    .permitAll() // 로그인 관련 페이지 에서는 인증을 요구 하지 않음.

        );


        // 로그아웃
        http.logout(
                logout -> logout
                        .logoutUrl("/logout") // 로그아웃 처리 URL
                        .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동시킬 페이지
                        // 로그아웃 핸들러
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession httpSession = request.getSession();
                                httpSession.invalidate();
                            }
                        })
                        // 로그아웃 성공 핸들러
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                System.out.println("로그아웃 성공");
                                response.sendRedirect("/login");
                            }
                        })
                        .deleteCookies("remember-me") // 로그아웃 후 쿠키 삭제
        );

        // rembmerme
        http.rememberMe(
            remember -> remember
                    .rememberMeParameter("remember") // remember-me 파라미터 이름 설정, 기본 파라미터명은 remember-me
                    .tokenValiditySeconds(3600) // 쿠키 만료 시간 60분으로 설정,  Default : 14일
                    .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                    .userDetailsService(userDetailsService) // 사용자 객체를 조회
        );

        // 세션 제어
        http.sessionManagement(
            (session) -> session
                    // 세션 정책
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)

                    // 세션 고정 보호
                    .sessionFixation().changeSessionId()

                    // 동시 세션 제어
                    .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 때 이동 할 페이지
                    .maximumSessions(1) // 최대 허용 가능 세션 수 , -1 : 무제한 허용
                    .maxSessionsPreventsLogin(true) // 최대 동시 접석 허용 세션 수를 초과한 경우 동시 접속 차단
                    .expiredUrl("/expired") // 세션이 만료된 경우 이동 할 페이지

        );


        return http.build();

    }

}
