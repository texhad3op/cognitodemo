package com.rzero.cognitodemo.cognitodemo.config.jwt;

import com.rzero.cognitodemo.cognitodemo.services.CognitoClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class AwsCognitoJwtAuthFilter extends GenericFilter {

    private static final String AUTH_ERROR = "Authorization header cognito bearer is empty";
    private static final String EMAIL = "email";

    private final AwsCognitoIdTokenProcessor cognitoIdTokenProcessor;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final CognitoClientService cognitoClientService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            String uri = httpServletRequest.getRequestURI();
            if (uri.equals("/error")) {
                authenticationEntryPoint.commence((HttpServletRequest) request, (HttpServletResponse) response, new AuthenticationServiceException(AUTH_ERROR));
            }
            boolean isSecuredApi = uri.startsWith("/api/secured/");
            if (isSecuredApi) {
                Authentication authentication = cognitoIdTokenProcessor.authenticate((HttpServletRequest) request);
                if (Objects.isNull(authentication)) {
                    throw new Exception("Authorization header cognito bearer is empty");
                } else {
                    String email = getEmailFromClaims(authentication);
                    if (!cognitoClientService.getCognitoUser(email).isPresent()) {
                        throw new Exception("The user doesn't exists in Cognito!");
                    }
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            log.error("Cognito idToken processing error", e);
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence((HttpServletRequest) request, (HttpServletResponse) response, new AuthenticationServiceException(e.getMessage()));
        }
        filterChain.doFilter(request, response);
    }

    private String getEmailFromClaims(Authentication authentication) {
        return (String) ((JwtAuthentication) authentication).getJwtClaimsSet().getClaims().get(EMAIL);
    }

}

