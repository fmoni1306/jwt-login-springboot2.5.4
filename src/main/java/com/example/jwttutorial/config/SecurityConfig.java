package com.example.jwttutorial.config;

import com.example.jwttutorial.jwt.JwtAccessDeniedHandler;
import com.example.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import com.example.jwttutorial.jwt.JwtSecurityConfig;
import com.example.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// 웹 보안을 활성화
@EnableWebSecurity
// @PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해서 적용
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // extends WebSecurityConfigurerAdapter 또는
    // implements WebSecurityConfigurer

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // 생성자 주입
    public SecurityConfig(TokenProvider tokenProvider,
                          JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    // 패스워드 인코더
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // h2 콘솔 접근은 Spring-Security 로직을 수행하지 않도록 하는 설정
        web.ignoring()
                .antMatchers("/h2-console/**", "/favicon.ico");

    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                // 토큰을 사용하기 때문에 csrf 설정은 disable
                .csrf().disable()

                // Exception 핸들링을 위해 만들었떤 클래스 추가
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // h2-console 을 위한 설정을 추가
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // session을 사용하지 않기 때문에 세션설정을 STATELESS로
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                // httpServletRequest 에 대한 요청들에 대한 설정하겠다.
                .authorizeRequests()
                // 인증없이 접근을 허용하겠다.
                .antMatchers("/api/hello").permitAll()
                // 인증없이 접근을 허용하겠다. 토큰사용없이 해야하는 서비스
                .antMatchers("/api/authenticate").permitAll()
                // 인증없이 접근을 허용하겠다. 토큰 사용없이 해야하는 서비스
                .antMatchers("/api/signup").permitAll()

                .anyRequest().authenticated() // 나머지 요청들은 모두 인증되어야한다.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));


    }


}
