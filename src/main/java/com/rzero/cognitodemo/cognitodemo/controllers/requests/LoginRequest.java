package com.rzero.cognitodemo.cognitodemo.controllers.requests;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest extends LogoutRequest{
    protected String password;
}
