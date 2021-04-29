package com.rzero.cognitodemo.cognitodemo.services;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LoginRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.LogoutRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.requests.RefreshTokenRequest;
import com.rzero.cognitodemo.cognitodemo.controllers.responses.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CognitoClientService {
    //
//    private static final String SEARCH_BY_EMAIL = "email=\"%s\"";
    private static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    private static final String USERNAME = "USERNAME";
    private static final String PASSWORD = "PASSWORD";
    //    private static final String NEW_PASSWORD = "NEW_PASSWORD";
//    private static final String NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED";
//    private static final String FORCE_CHANGE_PASSWORD = "FORCE_CHANGE_PASSWORD";
//    private static final String COGNITO_USER_CONFIRMED = "CONFIRMED";
//
    @Value("${rzero.jwt.user-pool-id}")
    private String cognitoUserPoolId;

    @Value("${rzero.jwt.user-pool-app-client-id}")
    private String cognitoUserPoolAppClientId;
    //
//    @Value("${spring.cognito.customer-portal.user-pool-id}")
//    private String cognitoCustomerPortalUserPoolId;
//
    private final AWSCognitoIdentityProvider cognitoIdentityProvider;

    //    private final InternationalizationService internationalizationService;
//
//    public UserType resendPasswordCognitoUser(UserProfileCreateRequest req, String tmpPassword) throws UsernameExistsException {
//        return processCognitoUser(req, tmpPassword, a -> {
//            a.withMessageAction(MessageActionType.RESEND);
//            return a;
//        });
//    }
//
//    public UserType createCognitoUser(UserProfileCreateRequest req, String tmpPassword) throws UsernameExistsException {
//        return processCognitoUser(req, tmpPassword, a -> {
//            a.withMessageAction(MessageActionType.SUPPRESS);
//            return a;
//        });
//    }
//
//    private UserType processCognitoUser(UserProfileCreateRequest req, String tmpPassword, Function<AdminCreateUserRequest, AdminCreateUserRequest> function) throws UsernameExistsException {
//        AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
//                .withUserPoolId(cognitoUserPoolId).
//                        withUsername(req.getEmail()).
//                        withUserAttributes(
//                                new AttributeType()
//                                        .withName("given_name")
//                                        .withValue(req.getFirstName()),
//                                new AttributeType()
//                                        .withName("family_name")
//                                        .withValue(req.getLastName()),
//                                new AttributeType()
//                                        .withName("email")
//                                        .withValue(req.getEmail()),
//                                new AttributeType()
//                                        .withName("email_verified")
//                                        .withValue("true")
//                        ).withTemporaryPassword(tmpPassword)
//                .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
//                .withForceAliasCreation(Boolean.FALSE);
//        cognitoRequest = function.apply(cognitoRequest);
//        AdminCreateUserResult createUserResult = cognitoIdentityProvider.adminCreateUser(cognitoRequest);
//        return createUserResult.getUser();
//    }
//
//    public void confirmCognitoUser(ChangeTemporaryPasswordRequest req) {
//        try {
//            AdminInitiateAuthResult result = cognitoIdentityProvider.adminInitiateAuth(new AdminInitiateAuthRequest()
//                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
//                    .withClientId(cognitoUserPoolAppClientId)
//                    .withUserPoolId(cognitoUserPoolId).
//                            withAuthParameters(getLoginParameters(req)));
//            if (!NEW_PASSWORD_REQUIRED.equals(result.getChallengeName())) {
//                throw new CognitoUserAlreadyConfirmedException(internationalizationService.getMessage("profile.creation.cognito.login.already.confirmed", req.getEmail()));
//            }
//            final AdminRespondToAuthChallengeRequest changePasswordRequest =
//                    new AdminRespondToAuthChallengeRequest();
//            changePasswordRequest.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
//                    .withChallengeResponses(getLoginParameters(req))
//                    .withClientId(cognitoUserPoolAppClientId)
//                    .withUserPoolId(cognitoUserPoolId)
//                    .withSession(result.getSession());
//
//            AdminRespondToAuthChallengeResult resultChallenge =
//                    cognitoIdentityProvider.adminRespondToAuthChallenge(changePasswordRequest);
//            resultChallenge.getAuthenticationResult();
//        } catch (NotAuthorizedException e) {
//            throw new CognitoUserDoesNotExistException(internationalizationService.getMessage("profile.creation.cognito.login.not.exists", req.getEmail()), e);
//        } catch (InvalidPasswordException e) {
//            throw new InvalidCognitoPasswordException(getInvalidPasswordExceptionMessage(e.getMessage()));
//        }
//    }
//
//    private String getInvalidPasswordExceptionMessage(String msg) {
//        int index = msg.indexOf("(");
//        return index == -1 ? msg : msg.substring(0, index);
//    }
//
//    private Map<String, String> getLoginParameters(ChangeTemporaryPasswordRequest req) {
//        final Map<String, String> authParams = new HashMap<>();
//        authParams.put(USERNAME, req.getEmail());
//        authParams.put(PASSWORD, req.getTemporaryPassword());
//        authParams.put(NEW_PASSWORD, req.getPassword());
//        return authParams;
//    }
//
//    public UserStateResponse getCognitoUserState(String email) {
//        return getCognitoUser(email).map(res -> new UserStateResponse(res.getUserStatus().equals(COGNITO_USER_CONFIRMED) ? UserStateResponse.State.CONFIRMED : UserStateResponse.State.NOT_CONFIRMED)).orElseGet(() ->
//                new UserStateResponse(UserStateResponse.State.NOT_EXISTS)
//        );
//    }
//
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

    //
//    public void deleteCognitoUser(String login) {
//        AdminGetUserResult res = getCognitoUser(login).orElseThrow(() -> new CognitoUserDoesNotExistException(internationalizationService.getMessage("profile.creation.cognito.login.not.exists", login)));
//        if (res.getUserStatus().equals(FORCE_CHANGE_PASSWORD)) {
//            AdminDeleteUserResult result = cognitoIdentityProvider.adminDeleteUser(new AdminDeleteUserRequest().withUserPoolId(cognitoUserPoolId).withUsername(login));
//            if (result.getSdkHttpMetadata().getHttpStatusCode() != HttpStatus.OK.value()) {
//                throw new CognitoUserCanNotBeDeletedException(internationalizationService.getMessage("profile.creation.cognito.user.delete.error", login));
//            }
//        } else {
//            throw new CognitoUserNotAppropriatedStateException(internationalizationService.getMessage("profile.creation.cognito.not.unconfirmed.state", login));
//        }
//    }
//
//    public void resetUserPassword(String username, String password) {
//        cognitoIdentityProvider.adminSetUserPassword(new AdminSetUserPasswordRequest().withUserPoolId(cognitoCustomerPortalUserPoolId)
//                .withPassword(password).withUsername(username).withPermanent(false));
//    }
//
//    public void userGlobalSignOut(String username) {
//        cognitoIdentityProvider.adminUserGlobalSignOut(new AdminUserGlobalSignOutRequest().withUserPoolId(cognitoUserPoolId).withUsername(username));
//    }
//
    public LoginResponse login(LoginRequest req) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put(USERNAME, req.getLogin());
        authParams.put(PASSWORD, req.getPassword());
        AdminInitiateAuthResult result = adminFlow(authParams, AuthFlowType.ADMIN_NO_SRP_AUTH);
        return getLoginResponse(result);
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

    public LoginResponse refreshJwt(RefreshTokenRequest req) {
        Map<String, String> authParams = new HashMap<>();
        authParams.put(REFRESH_TOKEN, req.getRefreshToken());
        AdminInitiateAuthResult result = adminFlow(authParams, AuthFlowType.REFRESH_TOKEN_AUTH);
        return getLoginResponse(result);
    }
}
