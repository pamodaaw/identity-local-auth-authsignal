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

package org.wso2.carbon.identity.local.auth.authsignal.executor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ActionState;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Executor;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.GetActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.user.api.UserStoreException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * Flow executor that adds Authsignal to registration, invited user registration and password recovery flows.
 * <p>
 * In registration flows the WSO2 user does not exist yet, so the executor generates the Authsignal user ID and
 * returns it as the {@link AuthsignalConstants#AUTHSIGNAL_USER_ID_CLAIM} claim, which is stored when the user is
 * created. The authenticator and later flows use that claim, so the authenticators enrolled during registration are
 * used at sign-in. In other flows the user already exists and the ID is resolved like in the authenticator.
 * <p>
 * The hosted portal resumes a flow after an external redirection only with the {@code code} and {@code state}
 * parameters, and ignores the {@code token} Authsignal appends. The executor therefore puts its own one-time
 * {@code code} and {@code state} in the redirect URL, and reads the challenge result server to server using the
 * action identifiers kept in the flow context.
 * <p>
 * Like the Email OTP executor, it needs no connection: it implements {@code Executor} directly and declares no
 * associated authenticator. The flow management API reports an executor as requiring a connection when it extends
 * {@code AuthenticationExecutor} or has an associated authenticator, and the Console then asks for one.
 */
public class AuthsignalExecutor implements org.wso2.carbon.identity.flow.execution.engine.graph.Executor {

    private static final Log LOG = LogFactory.getLog(AuthsignalExecutor.class);

    private static final String[] PENDING_CHALLENGE_PROPERTIES = {Executor.CONTEXT_PROP_USER_ID,
            Executor.CONTEXT_PROP_ACTION_CODE, Executor.CONTEXT_PROP_IDEMPOTENCY_KEY, Executor.CONTEXT_PROP_STATE,
            Executor.CONTEXT_PROP_CODE};

    @Override
    public String getName() {

        return Executor.EXECUTOR_NAME;
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return EnumSet.of(FlowTypes.REGISTRATION, FlowTypes.INVITED_USER_REGISTRATION, FlowTypes.PASSWORD_RECOVERY);
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(AuthsignalConstants.AUTHENTICATOR_FRIENDLY_NAME)
                .description(Executor.EXECUTOR_DESCRIPTION)
                .connectionRequired(false)
                .build();
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        if (context.getProperty(Executor.CONTEXT_PROP_STATE) != null) {
            return processChallengeResult(context);
        }
        return trackAction(context);
    }

    /**
     * Remove the Authsignal user enrolled in this registration flow when the flow is rolled back, so that a user that
     * is never created does not leave an orphan on Authsignal. Best effort.
     */
    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        String generatedUserId = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
        boolean enrolled = Boolean.TRUE.equals(context.getProperty(Executor.CONTEXT_PROP_ENROLLED));
        clearPendingChallenge(context);
        removeProperty(context, Executor.CONTEXT_PROP_GENERATED_USER_ID);
        removeProperty(context, Executor.CONTEXT_PROP_ENROLLED);
        if (generatedUserId == null || !enrolled) {
            return null;
        }
        try {
            createClient(resolveConfig(context.getTenantDomain())).deleteUser(generatedUserId);
        } catch (AuthsignalClientException | IdentityGovernanceException | RuntimeException e) {
            LOG.warn("Unable to remove the Authsignal user enrolled in a rolled back registration flow.", e);
        }
        return null;
    }

    /**
     * Track the flow's action on Authsignal and act on the returned decision.
     */
    private ExecutorResponse trackAction(FlowExecutionContext context) {

        String flowType = context.getFlowType();
        if (!isSupportedFlowType(flowType)) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_UNSUPPORTED_FLOW_TYPE,
                    String.format(ErrorMessages.ERROR_CODE_UNSUPPORTED_FLOW_TYPE.getMessage(), flowType), null);
        }
        String portalUrl = context.getPortalUrl();
        if (StringUtils.isBlank(portalUrl)) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_PORTAL_URL_NOT_FOUND, null);
        }

        AuthsignalConfig config;
        try {
            config = resolveConfig(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_READING_CONFIG, e);
        }
        if (StringUtils.isBlank(config.getSecretKey())) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED, null);
        }

        String authsignalUserId;
        try {
            authsignalUserId = resolveAuthsignalUserId(context, config);
        } catch (UserStoreException | RuntimeException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_READING_USER_ID_MAPPING, e);
        }
        if (authsignalUserId == null) {
            // Registration: the claim that stores the generated ID is missing. Other flows: the user does not exist,
            // reported generically to avoid user enumeration.
            return Executor.REGISTRATION.equals(flowType)
                    ? errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_USER_ID_CLAIM_NOT_CONFIGURED, null)
                    : errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_USER_NOT_IDENTIFIED, null);
        }

        String actionCode = getActionCode(flowType, config);
        String state = UUID.randomUUID().toString();
        String code = UUID.randomUUID().toString();
        TrackActionRequest trackRequest = new TrackActionRequest()
                .setRedirectUrl(buildRedirectUrl(portalUrl, code, state))
                .setUsername(getUsername(context));
        if (config.isRedirectToSettings()) {
            trackRequest.setRedirectToSettings(true);
        }
        populateContactDetails(trackRequest, context, config);

        TrackActionResponse trackResponse;
        try {
            trackResponse = createClient(config).trackAction(authsignalUserId, actionCode, trackRequest);
        } catch (AuthsignalClientException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_TRACK_ACTION_FAILED, e);
        }

        String actionState = trackResponse.getState();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal returned state: " + actionState + " for action: " + actionCode + " in flow type: "
                    + flowType);
        }
        if (ActionState.ALLOW.equals(actionState)
                || (ActionState.REVIEW_REQUIRED.equals(actionState) && config.isAllowOnReviewRequired())) {
            return completeResponse(context, authsignalUserId);
        }
        if (ActionState.BLOCK.equals(actionState)) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_ACTION_BLOCKED, null);
        }
        if (ActionState.REVIEW_REQUIRED.equals(actionState)) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_ACTION_REVIEW_REQUIRED, null);
        }
        if (!ActionState.CHALLENGE_REQUIRED.equals(actionState)) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_UNEXPECTED_ACTION_STATE,
                    String.format(ErrorMessages.ERROR_CODE_UNEXPECTED_ACTION_STATE.getMessage(), actionState), null);
        }

        // The pre-built UI lets an unenrolled user enrol a new authenticator. In password recovery that would let
        // whoever started the flow enrol their own authenticator and pass the check, so only enrolled users continue.
        if (Executor.PASSWORD_RECOVERY.equals(flowType) && !Boolean.TRUE.equals(trackResponse.getIsEnrolled())) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_USER_NOT_ENROLLED, null);
        }
        if (StringUtils.isBlank(trackResponse.getUrl()) || StringUtils.isBlank(trackResponse.getIdempotencyKey())) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_TRACK_ACTION_FAILED,
                    "Authsignal did not return a challenge URL.", null);
        }

        context.setProperty(Executor.CONTEXT_PROP_USER_ID, authsignalUserId);
        context.setProperty(Executor.CONTEXT_PROP_ACTION_CODE, actionCode);
        context.setProperty(Executor.CONTEXT_PROP_IDEMPOTENCY_KEY, trackResponse.getIdempotencyKey());
        context.setProperty(Executor.CONTEXT_PROP_STATE, state);
        context.setProperty(Executor.CONTEXT_PROP_CODE, code);

        ExecutorResponse response = newResponse(STATUS_EXTERNAL_REDIRECTION);
        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, trackResponse.getUrl());
        // The hosted portal maps the state to the flow ID so it can resume the flow on return.
        additionalInfo.put(Executor.STATE_PARAM, state);
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Arrays.asList(Executor.CODE_PARAM, Executor.STATE_PARAM));
        return response;
    }

    /**
     * Handle the return from the pre-built UI. The returned {@code code} and {@code state} only prove the request
     * belongs to this flow; the result itself is read from Authsignal using the identifiers kept in the context.
     */
    private ExecutorResponse processChallengeResult(FlowExecutionContext context) {

        String expectedState = (String) context.getProperty(Executor.CONTEXT_PROP_STATE);
        String expectedCode = (String) context.getProperty(Executor.CONTEXT_PROP_CODE);
        String authsignalUserId = (String) context.getProperty(Executor.CONTEXT_PROP_USER_ID);
        String actionCode = (String) context.getProperty(Executor.CONTEXT_PROP_ACTION_CODE);
        String idempotencyKey = (String) context.getProperty(Executor.CONTEXT_PROP_IDEMPOTENCY_KEY);
        // A challenge result can only be consumed once.
        clearPendingChallenge(context);

        Map<String, String> inputs = context.getUserInputData();
        String state = inputs != null ? inputs.get(Executor.STATE_PARAM) : null;
        String code = inputs != null ? inputs.get(Executor.CODE_PARAM) : null;
        if (!constantTimeEquals(expectedState, state) || !constantTimeEquals(expectedCode, code)
                || StringUtils.isBlank(authsignalUserId) || StringUtils.isBlank(actionCode)
                || StringUtils.isBlank(idempotencyKey)) {
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_INVALID_CALLBACK, null);
        }

        GetActionResponse action;
        try {
            AuthsignalConfig config = resolveConfig(context.getTenantDomain());
            action = createClient(config).getAction(authsignalUserId, actionCode, idempotencyKey);
        } catch (IdentityGovernanceException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_READING_CONFIG, e);
        } catch (AuthsignalClientException e) {
            return errorResponse(STATUS_ERROR, ErrorMessages.ERROR_CODE_GET_ACTION_FAILED, e);
        }

        if (!ActionState.CHALLENGE_SUCCEEDED.equals(action.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal action is in state: " + action.getState());
            }
            return errorResponse(STATUS_USER_ERROR, ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED, null);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal challenge succeeded using verification method: " + action.getVerificationMethod());
        }
        if (authsignalUserId.equals(context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID))) {
            context.setProperty(Executor.CONTEXT_PROP_ENROLLED, true);
        }
        return completeResponse(context, authsignalUserId);
    }

    private ExecutorResponse completeResponse(FlowExecutionContext context, String authsignalUserId) {

        ExecutorResponse response = newResponse(STATUS_COMPLETE);
        // Store the generated ID on the user so every later flow and sign-in uses the same Authsignal user.
        if (authsignalUserId.equals(context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID))) {
            Map<String, Object> updatedClaims = new HashMap<>();
            updatedClaims.put(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM, authsignalUserId);
            response.setUpdatedUserClaims(updatedClaims);
        }
        return response;
    }

    /**
     * Resolve the Authsignal user ID of the flow user.
     *
     * @return The ID, or null if it cannot be resolved: in registration flows when the claim that stores it is not
     * configured, otherwise when the user does not exist.
     */
    protected String resolveAuthsignalUserId(FlowExecutionContext context, AuthsignalConfig config)
            throws UserStoreException {

        String tenantDomain = context.getTenantDomain();
        FlowUser flowUser = getFlowUser(context);

        if (Executor.REGISTRATION.equals(context.getFlowType())) {
            if (!isUserIdClaimConfigured(tenantDomain)) {
                return null;
            }
            // Reuse the ID generated earlier in this flow so that a retried step does not create another user.
            String generatedUserId = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
            if (generatedUserId == null) {
                generatedUserId = UUID.randomUUID().toString();
                context.setProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID, generatedUserId);
            }
            return generatedUserId;
        }

        String username = getUsername(context);
        if (username == null) {
            return null;
        }
        String userStoreDomain = flowUser.getUserStoreDomain();
        String userId = StringUtils.isNotBlank(flowUser.getUserId()) ? flowUser.getUserId()
                : getUserId(tenantDomain, userStoreDomain, username);
        if (StringUtils.isBlank(userId)) {
            return null;
        }

        String mappedUserId = getMappedUserId(tenantDomain, userStoreDomain, username);
        if (mappedUserId != null) {
            return mappedUserId;
        }
        String identifier = config.getUserIdentifier();
        if (AuthsignalConstants.UserIdentifier.USER_ID.equalsIgnoreCase(identifier)) {
            return userId;
        }
        if (AuthsignalConstants.UserIdentifier.USERNAME.equalsIgnoreCase(identifier)) {
            return AuthsignalUserIdResolver.toQualifiedUsername(username, userStoreDomain, tenantDomain);
        }
        throw new IllegalStateException(
                String.format(ErrorMessages.ERROR_CODE_INVALID_USER_IDENTIFIER.getMessage(), identifier));
    }

    protected boolean isUserIdClaimConfigured(String tenantDomain) throws UserStoreException {

        return AuthsignalUserIdResolver.isUserIdClaimConfigured(tenantDomain);
    }

    protected String getMappedUserId(String tenantDomain, String userStoreDomain, String username)
            throws UserStoreException {

        return AuthsignalUserIdResolver.getMappedUserId(tenantDomain, userStoreDomain, username);
    }

    protected String getUserId(String tenantDomain, String userStoreDomain, String username)
            throws UserStoreException {

        return AuthsignalUserIdResolver.getUserId(tenantDomain, userStoreDomain, username);
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalConfigResolver.resolve(tenantDomain);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

        String apiBaseUrl = config.getApiBaseUrl();
        if (apiBaseUrl == null) {
            throw new AuthsignalClientException(
                    String.format(ErrorMessages.ERROR_CODE_INVALID_REGION.getMessage(), config.getRegion()));
        }
        return new AuthsignalClient(apiBaseUrl, config.getSecretKey(), config.getRequestTimeoutMillis());
    }

    /**
     * Pre-fill the email and mobile number entered during registration so Authsignal can offer them for enrolment.
     * Authsignal verifies them before use. Not done in password recovery, where only enrolled authenticators may be
     * used.
     */
    private void populateContactDetails(TrackActionRequest trackRequest, FlowExecutionContext context,
                                        AuthsignalConfig config) {

        if (Executor.PASSWORD_RECOVERY.equals(context.getFlowType())) {
            return;
        }
        FlowUser flowUser = getFlowUser(context);
        if (config.isSendEmail()) {
            trackRequest.setEmail(getClaim(flowUser, AuthsignalConstants.EMAIL_CLAIM));
        }
        String mobile = getClaim(flowUser, AuthsignalConstants.MOBILE_CLAIM);
        // Authsignal expects E.164 numbers; skip values that are not in that format.
        if (config.isSendPhoneNumber() && mobile != null && mobile.startsWith("+")) {
            trackRequest.setPhoneNumber(mobile);
        }
    }

    /**
     * Get the username of the flow user. In registration flows only the entered username claim is read:
     * {@link FlowUser#getUsername()} would otherwise derive one (falling back to a generated value) before the flow
     * has collected all the user's attributes.
     */
    private static String getUsername(FlowExecutionContext context) {

        FlowUser flowUser = getFlowUser(context);
        if (Executor.REGISTRATION.equals(context.getFlowType())) {
            return getClaim(flowUser, USERNAME_CLAIM_URI);
        }
        return StringUtils.trimToNull(flowUser.getUsername());
    }

    private static String getClaim(FlowUser flowUser, String claimUri) {

        Object value = flowUser.getClaim(claimUri);
        return value != null ? StringUtils.trimToNull(String.valueOf(value)) : null;
    }

    private static FlowUser getFlowUser(FlowExecutionContext context) {

        return context.getFlowUser() != null ? context.getFlowUser() : new FlowUser();
    }

    private static String getActionCode(String flowType, AuthsignalConfig config) {

        return Executor.PASSWORD_RECOVERY.equals(flowType) ? config.getRecoveryActionCode()
                : config.getRegistrationActionCode();
    }

    private static boolean isSupportedFlowType(String flowType) {

        return isRegistration(flowType) || Executor.PASSWORD_RECOVERY.equals(flowType);
    }

    private static boolean isRegistration(String flowType) {

        return Executor.REGISTRATION.equals(flowType) || Executor.INVITED_USER_REGISTRATION.equals(flowType);
    }

    /**
     * Append the executor's {@code code} and {@code state} to the portal URL. Authsignal appends its own {@code token}
     * parameter to this URL, which the portal ignores.
     */
    static String buildRedirectUrl(String portalUrl, String code, String state) {

        int fragmentIndex = portalUrl.indexOf('#');
        String base = fragmentIndex >= 0 ? portalUrl.substring(0, fragmentIndex) : portalUrl;
        String separator = base.contains("?") ? (base.endsWith("?") || base.endsWith("&") ? "" : "&") : "?";
        return base + separator + Executor.CODE_PARAM + "=" + encode(code) + "&" + Executor.STATE_PARAM + "="
                + encode(state);
    }

    private static String encode(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(String expected, String actual) {

        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static void clearPendingChallenge(FlowExecutionContext context) {

        for (String property : PENDING_CHALLENGE_PROPERTIES) {
            removeProperty(context, property);
        }
    }

    private static void removeProperty(FlowExecutionContext context, String property) {

        if (context.getProperties() != null) {
            context.getProperties().remove(property);
        }
    }

    private static ExecutorResponse newResponse(String status) {

        // Only the no-argument constructor initializes the error details.
        ExecutorResponse response = new ExecutorResponse();
        response.setResult(status);
        return response;
    }

    private static ExecutorResponse errorResponse(String status, ErrorMessages error, Throwable cause) {

        return errorResponse(status, error, error.getMessage(), cause);
    }

    private static ExecutorResponse errorResponse(String status, ErrorMessages error, String message,
                                                  Throwable cause) {

        if (cause != null) {
            LOG.error(error.getCode() + " - " + message, cause);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug(error.getCode() + " - " + message);
        }
        ExecutorResponse response = newResponse(status);
        response.setErrorCode(error.getCode());
        response.setErrorMessage(message);
        response.setErrorDescription(message);
        if (cause != null) {
            response.setThrowable(cause);
        }
        return response;
    }
}
