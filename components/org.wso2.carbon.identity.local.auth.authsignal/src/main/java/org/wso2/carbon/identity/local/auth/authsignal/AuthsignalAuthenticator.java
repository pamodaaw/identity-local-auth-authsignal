/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.authsignal;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ActionState;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.ValidateChallengeResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.CONTEXT_PROP_AUTHSIGNAL_USER_ID;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.CONTEXT_PROP_IDEMPOTENCY_KEY;

/**
 * Local authenticator that adds Authsignal adaptive MFA to a WSO2 Identity Server login flow.
 * <p>
 * The authenticator must be placed after a step that identifies the user. It:
 * <ol>
 *     <li>Tracks a sign-in action for the user on Authsignal. Authsignal evaluates its rules and returns
 *     {@code ALLOW}, {@code BLOCK}, {@code REVIEW_REQUIRED} or {@code CHALLENGE_REQUIRED}.</li>
 *     <li>On {@code CHALLENGE_REQUIRED}, redirects the user to the Authsignal pre-built UI with the WSO2
 *     {@code /commonauth} endpoint as the redirect URL.</li>
 *     <li>When the user returns with the {@code token} query parameter, validates the token server side and
 *     completes the step only if the challenge succeeded for the same user and action.</li>
 * </ol>
 */
public class AuthsignalAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4127094857123698412L;
    private static final Log LOG = LogFactory.getLog(AuthsignalAuthenticator.class);

    @Override
    public String getName() {

        return AuthsignalConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AuthsignalConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getI18nKey() {

        return AuthsignalConstants.AUTHENTICATOR_I18N_KEY;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(AuthsignalConstants.SESSION_DATA_KEY);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(AuthsignalConstants.TOKEN_PARAM));
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        // A failed or blocked Authsignal decision must fail the flow rather than silently re-challenging.
        return false;
    }

    @Override
    protected boolean retryAuthenticationEnabled(AuthenticationContext context) {

        return false;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // The user is returning from the Authsignal pre-built UI for a challenge this flow initiated.
        if (isChallengeCallback(request, context)) {
            return super.process(request, response, context);
        }

        return trackSignInAction(request, response, context);
    }

    /**
     * Not reached in practice: {@link #process} handles initiation itself so that an Authsignal ALLOW decision can
     * complete the step without a redirect, and retry is disabled.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        trackSignInAction(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getAuthenticatedUserFromContext(context);
        if (user == null) {
            throw failure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        String token = request.getParameter(AuthsignalConstants.TOKEN_PARAM);
        if (StringUtils.isBlank(token)) {
            throw failure(ErrorMessages.ERROR_CODE_MISSING_TOKEN, user);
        }

        String expectedUserId = (String) context.getProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID);
        String expectedIdempotencyKey = (String) context.getProperty(CONTEXT_PROP_IDEMPOTENCY_KEY);
        // The challenge can only be consumed once.
        context.removeProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID);
        context.removeProperty(CONTEXT_PROP_IDEMPOTENCY_KEY);

        AuthsignalConfig config = getAuthsignalConfig(context);
        ValidateChallengeResponse result;
        try {
            result = createClient(config).validateChallenge(token, expectedUserId, config.getActionCode());
        } catch (AuthsignalClientException e) {
            throw failure(ErrorMessages.ERROR_CODE_VALIDATE_CHALLENGE_FAILED, user, e);
        }

        if (!result.isValid() || !ActionState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal challenge validation returned state: " + result.getState());
            }
            throw failure(ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED, user);
        }

        // Bind the token to the action tracked in this authentication context to prevent token replay or swapping.
        if (!StringUtils.equals(expectedUserId, result.getUserId())
                || !StringUtils.equals(expectedIdempotencyKey, result.getIdempotencyKey())) {
            throw failure(ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH, user);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal challenge succeeded using verification method: " + result.getVerificationMethod());
        }
        context.setSubject(new AuthenticatedUser(user));
    }

    /**
     * Track the sign-in action on Authsignal and act on the returned decision.
     */
    private AuthenticatorFlowStatus trackSignInAction(HttpServletRequest request, HttpServletResponse response,
                                                      AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = getAuthenticatedUserFromContext(context);
        if (user == null) {
            throw failure(ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER, null);
        }

        AuthsignalConfig config = getAuthsignalConfig(context);
        String authsignalUserId = resolveAuthsignalUserId(user, config);

        TrackActionRequest trackRequest = new TrackActionRequest()
                .setRedirectUrl(buildCallbackUrl(context))
                .setUsername(user.getUserName())
                .setIpAddress(IdentityUtil.getClientIpAddress(request))
                .setUserAgent(request.getHeader(AuthsignalConstants.USER_AGENT_HEADER));
        if (config.isRedirectToSettings()) {
            trackRequest.setRedirectToSettings(true);
        }
        populateContactDetails(trackRequest, user, config);

        TrackActionResponse trackResponse;
        try {
            trackResponse = createClient(config).trackAction(authsignalUserId, config.getActionCode(), trackRequest);
        } catch (AuthsignalClientException e) {
            throw failure(ErrorMessages.ERROR_CODE_TRACK_ACTION_FAILED, user, e);
        }

        String state = trackResponse.getState();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal returned state: " + state + " for action: " + config.getActionCode());
        }
        context.setCurrentAuthenticator(getName());

        if (ActionState.ALLOW.equals(state)
                || (ActionState.REVIEW_REQUIRED.equals(state) && config.isAllowOnReviewRequired())) {
            return completeWithoutChallenge(request, context, user);
        }
        if (ActionState.CHALLENGE_REQUIRED.equals(state)) {
            redirectToChallenge(response, context, user, authsignalUserId, trackResponse);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        if (ActionState.BLOCK.equals(state)) {
            throw failure(ErrorMessages.ERROR_CODE_ACTION_BLOCKED, user);
        }
        if (ActionState.REVIEW_REQUIRED.equals(state)) {
            throw failure(ErrorMessages.ERROR_CODE_ACTION_REVIEW_REQUIRED, user);
        }
        throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_UNEXPECTED_ACTION_STATE.getCode(),
                String.format(ErrorMessages.ERROR_CODE_UNEXPECTED_ACTION_STATE.getMessage(), state), user);
    }

    private AuthenticatorFlowStatus completeWithoutChallenge(HttpServletRequest request,
                                                             AuthenticationContext context, AuthenticatedUser user) {

        AuthenticatedUser subject = new AuthenticatedUser(user);
        context.setSubject(subject);
        context.setRetrying(false);
        request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
        publishAuthenticationStepAttempt(request, context, subject, true);
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    private void redirectToChallenge(HttpServletResponse response, AuthenticationContext context,
                                     AuthenticatedUser user, String authsignalUserId,
                                     TrackActionResponse trackResponse) throws AuthenticationFailedException {

        if (StringUtils.isBlank(trackResponse.getUrl())) {
            throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_TRACK_ACTION_FAILED.getCode(),
                    "Authsignal did not return a challenge URL.", user);
        }
        context.setProperty(CONTEXT_PROP_AUTHSIGNAL_USER_ID, authsignalUserId);
        context.setProperty(CONTEXT_PROP_IDEMPOTENCY_KEY, trackResponse.getIdempotencyKey());
        try {
            response.sendRedirect(trackResponse.getUrl());
        } catch (IOException e) {
            throw failure(ErrorMessages.ERROR_CODE_REDIRECTING, user, e);
        }
    }

    private boolean isChallengeCallback(HttpServletRequest request, AuthenticationContext context) {

        // REQ_ATTR_HANDLED is set when a previous step already consumed this request in the same round trip.
        return canHandle(request)
                && context.getProperty(CONTEXT_PROP_IDEMPOTENCY_KEY) != null
                && !Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED));
    }

    /**
     * Build the URL Authsignal redirects the user back to after the challenge. Authsignal appends the
     * {@code token} query parameter to it.
     */
    protected String buildCallbackUrl(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create()
                    .addPath(FrameworkConstants.COMMONAUTH)
                    .addParameter(AuthsignalConstants.SESSION_DATA_KEY, context.getContextIdentifier())
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw failure(ErrorMessages.ERROR_CODE_BUILDING_CALLBACK_URL, null, e);
        }
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthenticationFailedException {

        if (StringUtils.isBlank(config.getSecretKey())) {
            throw failure(ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED, null);
        }
        String apiBaseUrl = config.getApiBaseUrl();
        if (apiBaseUrl == null) {
            throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_INVALID_REGION.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_INVALID_REGION.getMessage(), config.getRegion()));
        }
        return new AuthsignalClient(apiBaseUrl, config.getSecretKey(), config.getRequestTimeoutMillis());
    }

    /**
     * Build the configuration from the governance connector properties of the tenant the authentication request
     * belongs to.
     */
    protected AuthsignalConfig getAuthsignalConfig(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return AuthsignalConfigResolver.resolve(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            throw failure(ErrorMessages.ERROR_CODE_READING_CONFIG, null, e);
        }
    }

    /**
     * Map the WSO2 user to the user ID known to Authsignal. The ID stored on the user when it enrolled during self
     * registration takes precedence over the configured strategy.
     */
    protected String resolveAuthsignalUserId(AuthenticatedUser user, AuthsignalConfig config)
            throws AuthenticationFailedException {

        if (user.isFederatedUser()) {
            return user.getAuthenticatedSubjectIdentifier();
        }

        String mappedUserId = getMappedAuthsignalUserId(user);
        if (mappedUserId != null) {
            return mappedUserId;
        }

        String identifier = config.getUserIdentifier();
        if (AuthsignalConstants.UserIdentifier.USER_ID.equalsIgnoreCase(identifier)) {
            try {
                return user.getUserId();
            } catch (UserIdNotFoundException e) {
                throw failure(ErrorMessages.ERROR_CODE_RESOLVING_USER_ID, user, e);
            }
        }
        if (AuthsignalConstants.UserIdentifier.USERNAME.equalsIgnoreCase(identifier)) {
            return AuthsignalUserIdResolver.toQualifiedUsername(user.getUserName(), user.getUserStoreDomain(),
                    user.getTenantDomain());
        }
        throw new AuthenticationFailedException(ErrorMessages.ERROR_CODE_INVALID_USER_IDENTIFIER.getCode(),
                String.format(ErrorMessages.ERROR_CODE_INVALID_USER_IDENTIFIER.getMessage(), identifier), user);
    }

    /**
     * Get the Authsignal user ID stored on the user, if any. Fails closed: if the mapping cannot be read, falling back
     * to another ID would present an enrolled user as unenrolled to Authsignal.
     */
    protected String getMappedAuthsignalUserId(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return AuthsignalUserIdResolver.getMappedUserId(user.getTenantDomain(), user.getUserStoreDomain(),
                    user.getUserName());
        } catch (UserStoreException | RuntimeException e) {
            throw failure(ErrorMessages.ERROR_CODE_READING_USER_ID_MAPPING, user, e);
        }
    }

    /**
     * Pre-fill the user's email and phone number so Authsignal can offer email / SMS verification methods.
     * Failure to read the claims does not block the login.
     */
    private void populateContactDetails(TrackActionRequest trackRequest, AuthenticatedUser user,
                                        AuthsignalConfig config) {

        if (user.isFederatedUser() || (!config.isSendEmail() && !config.isSendPhoneNumber())) {
            return;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
            UserRealm userRealm = AuthsignalAuthenticatorDataHolder.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm == null) {
                return;
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            String username = IdentityUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain());
            Map<String, String> claims = userStoreManager.getUserClaimValues(username,
                    new String[]{AuthsignalConstants.EMAIL_CLAIM, AuthsignalConstants.MOBILE_CLAIM}, null);
            if (claims == null) {
                return;
            }
            if (config.isSendEmail()) {
                trackRequest.setEmail(StringUtils.trimToNull(claims.get(AuthsignalConstants.EMAIL_CLAIM)));
            }
            String mobile = StringUtils.trimToNull(claims.get(AuthsignalConstants.MOBILE_CLAIM));
            // Authsignal expects E.164 numbers; skip values that are not in that format.
            if (config.isSendPhoneNumber() && mobile != null && mobile.startsWith("+")) {
                trackRequest.setPhoneNumber(mobile);
            }
        } catch (UserStoreException | RuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to read the contact details of the user to send to Authsignal.", e);
            }
        }
    }

    /**
     * Get the user identified by a previous step.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context) {

        if (context.getSequenceConfig() != null && context.getSequenceConfig().getStepMap() != null) {
            for (StepConfig stepConfig : context.getSequenceConfig().getStepMap().values()) {
                AuthenticatedUser user = stepConfig.getAuthenticatedUser();
                if (stepConfig.isSubjectAttributeStep() && user != null && user.getUserName() != null) {
                    return user;
                }
            }
        }
        AuthenticatedUser lastAuthenticatedUser = context.getLastAuthenticatedUser();
        if (lastAuthenticatedUser != null && lastAuthenticatedUser.getUserName() != null) {
            return lastAuthenticatedUser;
        }
        return null;
    }

    private static AuthenticationFailedException failure(ErrorMessages error, AuthenticatedUser user) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user);
    }

    private static AuthenticationFailedException failure(ErrorMessages error, AuthenticatedUser user,
                                                         Throwable cause) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), user, cause);
    }
}
