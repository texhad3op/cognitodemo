package com.rzero.cognitodemo.cognitodemo.controllers;

import com.rzero.cognitodemo.cognitodemo.controllers.requests.ChangeTemporaryPasswordRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LoginRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LogoutRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.RefreshTokenRequest;
import com.rzero.cognitodemo.cognitodemo.services.CognitoClientService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@AllArgsConstructor
@RestController
public class JWTRest {

    private final CognitoClientService cognito;

    @PostMapping("/api/public/confirm")
    public void confirmProfile(@RequestBody ChangeTemporaryPasswordRequest req) {
        cognito.confirmCognitoUser(req);
    }

    @PostMapping("/api/public/login")
    public ResponseEntity login(@RequestBody LoginRequest req) {
        return ResponseEntity.status(HttpStatus.OK).body(cognito.login(req));
    }

    @PostMapping("/api/public/logout")
    public ResponseEntity logout(HttpServletRequest request, @RequestBody LogoutRequest req) {
        cognito.logout(req);
        SecurityContextHolder.clearContext();
        request.getSession().invalidate();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/api/public/refresh-jwt")
    public ResponseEntity refreshJwt(@RequestBody RefreshTokenRequest req) {
        return ResponseEntity.status(HttpStatus.OK).body(cognito.refreshJwt(req));
    }

    @GetMapping("/api/public/check")
    public ResponseEntity publicCheck() {
        return ResponseEntity.status(HttpStatus.OK).body("Not secured. It is ok!");
    }

    @GetMapping("/api/secured/check")
    public ResponseEntity securedCheck() {
        return ResponseEntity.status(HttpStatus.OK).body("Secured. It is ok!");
    }
}
