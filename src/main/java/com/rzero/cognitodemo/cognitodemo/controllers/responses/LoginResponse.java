package com.rzero.cognitodemo.cognitodemo.controllers.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private String idToken;
    private String refreshToken;
    private String status;
    private String session;
}
