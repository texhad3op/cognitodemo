package com.rzero.cognitodemo.cognitodemo.services;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.ChangeTemporaryPasswordRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LoginRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LogoutRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.RefreshTokenRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.responses.LoginResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CognitoClientService {
    private static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    private static final String USERNAME = "USERNAME";
    private static final String PASSWORD = "PASSWORD";
    private static final String NEW_PASSWORD = "NEW_PASSWORD";
    private static final String NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED";

    @Value("${rzero.jwt.user-pool-id}")
    private String cognitoUserPoolId;

    @Value("${rzero.jwt.user-pool-app-client-id}")
    private String cognitoUserPoolAppClientId;

    private final AWSCognitoIdentityProvider cognitoIdentityProvider;

    public void confirmCognitoUser(ChangeTemporaryPasswordRequest req) {
        try {
            AdminInitiateAuthResult result = cognitoIdentityProvider.adminInitiateAuth(new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withClientId(cognitoUserPoolAppClientId)
                    .withUserPoolId(cognitoUserPoolId).
                            withAuthParameters(getLoginParameters(req)));
            if (!NEW_PASSWORD_REQUIRED.equals(result.getChallengeName())) {
                throw new RuntimeException("Error state");
            }
            final AdminRespondToAuthChallengeRequest changePasswordRequest =
                    new AdminRespondToAuthChallengeRequest();
            changePasswordRequest.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    .withChallengeResponses(getLoginParameters(req))
                    .withClientId(cognitoUserPoolAppClientId)
                    .withUserPoolId(cognitoUserPoolId)
                    .withSession(result.getSession());

            AdminRespondToAuthChallengeResult resultChallenge =
                    cognitoIdentityProvider.adminRespondToAuthChallenge(changePasswordRequest);
            resultChallenge.getAuthenticationResult();
        } catch (NotAuthorizedException e) {
            log.error("some error");
        }
    }

    private Map<String, String> getLoginParameters(ChangeTemporaryPasswordRequest req) {
        final Map<String, String> authParams = new HashMap<>();
        authParams.put(USERNAME, req.getEmail());
        authParams.put(PASSWORD, req.getTemporaryPassword());
        authParams.put(NEW_PASSWORD, req.getPassword());
        return authParams;
    }

    public Optional<AdminGetUserResult> getCognitoUser(String email) {
        try {
            AdminGetUserRequest adminGetUserRequest = new AdminGetUserRequest()
                    .withUserPoolId(cognitoUserPoolId)
                    .withUsername(email);
            return Optional.ofNullable(cognitoIdentityProvider.adminGetUser(adminGetUserRequest));
        } catch (UserNotFoundException e) {
            return Optional.ofNullable(null);
        }
    }

    private AdminInitiateAuthResult adminFlow(Map<String, String> authParams, AuthFlowType authFlowType) {
        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(authFlowType)
                .withClientId(cognitoUserPoolAppClientId)
                .withUserPoolId(cognitoUserPoolId)
                .withAuthParameters(authParams);
        return cognitoIdentityProvider.adminInitiateAuth(authRequest);
    }

    private LoginResponse getLoginResponse(AdminInitiateAuthResult result) {
        AuthenticationResultType resultType = result.getAuthenticationResult();
        return getLoginResponseFromType(resultType, result.getChallengeName(), result.getSession());
    }

    private LoginResponse getLoginResponseFromType(AuthenticationResultType resultType, String challengeName, String session) {
        return new LoginResponse(Objects.nonNull(resultType) ? resultType.getIdToken() : null, Objects.nonNull(resultType) ? resultType.getRefreshToken() : null, Objects.nonNull(challengeName) ? challengeName : "OK", session);
    }

    public void logout(LogoutRequest req) {
        cognitoIdentityProvider.adminUserGlobalSignOut(new AdminUserGlobalSignOutRequest().withUserPoolId(cognitoUserPoolId).withUsername(req.getLogin()));
    }

    public LoginResponse login(LoginRequest req) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put(USERNAME, req.getLogin());
        authParams.put(PASSWORD, req.getPassword());
        AdminInitiateAuthResult result = adminFlow(authParams, AuthFlowType.ADMIN_NO_SRP_AUTH);
        return getLoginResponse(result);
    }

    public LoginResponse refreshJwt(RefreshTokenRequest req) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put(REFRESH_TOKEN, req.getRefreshToken());
        AdminInitiateAuthResult result = adminFlow(authParams, AuthFlowType.REFRESH_TOKEN_AUTH);
        return getLoginResponse(result);
    }
}
