package com.rzero.cognitodemo.cognitodemo.controllers.requests;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChangeTemporaryPasswordRequest {
    private String email;
    private String temporaryPassword;
    private String password;
}
