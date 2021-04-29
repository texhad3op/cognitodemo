package com.rzero.cognitodemo.cognitodemo.config.jwt;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component
public class AwsCognitoIdTokenProcessor {

    private static final String BEARER = "Bearer ";
    private static final String COGNITO_USERNAME = "cognito:username";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Value("${rzero.jwt.jwks-url}")
    private String jwksUrl;

    @Value("${rzero.jwt.issuer}")
    private String issuer;

    @Autowired
    private ConfigurableJWTProcessor configurableJWTProcessor;

    public Authentication authenticate(HttpServletRequest request) throws Exception {
        String idToken = request.getHeader(AUTHORIZATION_HEADER);
        if (idToken != null) {
            JWTClaimsSet claims = configurableJWTProcessor.process(getBearerToken(idToken), null);
            validateIssuer(claims);
            String username = getUserNameFrom(claims);
            if (username != null) {
                List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
                User user = new User(username, "", List.of());
                return new JwtAuthentication(user, claims, grantedAuthorities);
            }
        }
        return null;
    }

    private String getUserNameFrom(JWTClaimsSet claims) {
        return claims.getClaims().get(COGNITO_USERNAME).toString();
    }

    private void validateIssuer(JWTClaimsSet claims) throws Exception {
        if (!claims.getIssuer().equals(issuer)) {
            throw new Exception(String.format("Issuer %s does not match cognito idp %s", claims.getIssuer(), jwksUrl));
        }
    }

    private String getBearerToken(String token) {
        return token.startsWith(BEARER) ? token.substring(BEARER.length()) : token;
    }
}
