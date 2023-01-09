package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    // json방식으로 요청 온 정보를 객체로 만든다
    private ObjectMapper objectMapper = new ObjectMapper();


    public AjaxLoginProcessingFilter() {
        // 아래 Url로 요청을 했을 때 매칭이 되면 필터가 작동되도록 함
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        // Ajax 인지 아닌지 확인
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }
        // 읽어온 정보를 dto 클래스 타입으로 담아서 받음
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        //dto에 username, password가 비어있으면 인증처리를 하면 안 됨
        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }

        // 인증처리는 Ajax용 인증 토큰을 만들어서 사용자 정보를 담는다
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        // 토큰을 AuthenticationManager에게 전달
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    /*
        사용자가 요청할 때 헤더에 정보를 담아서 보내는데 그 담긴 값과 같은지 아닌지 확인
     */
    private boolean isAjax(HttpServletRequest request) {

        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }

        return false;
    }
}
