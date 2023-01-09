package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.cert.Extension;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService); //직접 만든 service 넣어준다
        //스프링 시큐리티가 이 구현체를 사용해서 인증처리를 하게 된다

        auth.authenticationProvider(authenticationProvider());
    }

    /*
        이렇게 하면 스프링 시큐리티가 인증처리를 할 때
        우리가 만든 CustomAuthenticationProvider를 참조해서 인증 처리를 하게 된다
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    //사용자 추가 (메모리방식)
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//        // 패스워드 만들기 (PasswordEncoder 만들어야 함) -> 이제 패스워드 자동 생성 안 됨
//        String password = passwordEncoder().encode("1111");
//
//                //메모리 방식(DB X). 사용자 계정 생성(권한 다르게)
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","USER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "USER", "MANAGER");
//    }
    @Bean //인코더는 빈으로 만들기
    public PasswordEncoder passwordEncoder() {
        // 평문 -> 암호화
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //Web Ignore 설정
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 이 설정만 해주면 정적 파일들은 보안필터 거치지 않고 통과한다
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll() // 익명 사용자도 접근 가능
                .antMatchers("/mypage").hasRole("USER")   // 사용자 역할만 접근 가능
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()  //어떤 요청도 다 인증 받아야 한다

                .and()
                .formLogin()  // 디폴트 폼 로그인
                .loginPage("/login") // 커스텀 로그인 페이지
                .loginProcessingUrl("/login_proc") //login.html 폼의 action 이름과 일치
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")  //로그인 성공시 이동할 페이지
                .successHandler(customAuthenticationSuccessHandler) //핸들러가 인증 성공 후에 호출됨
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll();

        http    // 인가 예외가 발생했을 경우에 핸들러를 호출하도록 API 제공
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())

                .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        http.csrf().disable();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied"); //경로에 errorPage 설정

        return accessDeniedHandler;
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
        return ajaxLoginProcessingFilter;
    }
}
