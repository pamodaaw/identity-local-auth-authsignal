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

import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Executor;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.GetActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.user.api.UserStoreException;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link AuthsignalExecutor}.
 */
public class AuthsignalExecutorTest {

    private static final String TENANT = "carbon.super";
    private static final String PORTAL_URL = "https://localhost:9443/accounts/register?flowType=REGISTRATION";
    private static final String CHALLENGE_URL = "https://signin.authsignal.com/challenge";
    private static final String USER_UUID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";

    private AuthsignalClient client;
    private Map<String, String> tenantProperties;
    private boolean claimConfigured;
    private String mappedUserId;
    private String storeUserId;
    private TestableExecutor executor;

    @BeforeMethod
    public void setUp() {

        client = mock(AuthsignalClient.class);
        tenantProperties = new HashMap<>();
        tenantProperties.put(ConnectorConfig.SECRET_KEY, "secret");
        claimConfigured = true;
        mappedUserId = null;
        storeUserId = USER_UUID;
        executor = new TestableExecutor();
    }

    @Test
    public void testMetadata() {

        assertEquals(executor.getName(), "AuthsignalExecutor");
        // The flow management API reports requiresConnection = true for authentication executors and executors with
        // an associated authenticator, which makes the Console ask for a connection.
        assertFalse(AuthenticationExecutor.class.isAssignableFrom(AuthsignalExecutor.class));
        assertNull(executor.getExecutorMetadata().getAssociatedAuthenticator());
        assertFalse(executor.getExecutorMetadata().isConnectionRequired());
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.REGISTRATION));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.PASSWORD_RECOVERY));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.INVITED_USER_REGISTRATION));
        assertTrue(executor.getInitiationData().isEmpty());
    }

    @Test
    public void testRegistrationChallengeRedirectsWithGeneratedUserId() throws Exception {

        FlowExecutionContext context = registrationContext();
        challengeRequired(true);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        assertEquals(response.getAdditionalInfo().get("redirectUrl"), CHALLENGE_URL);
        String state = response.getAdditionalInfo().get("state");
        assertNotNull(state);
        assertTrue(response.getRequiredData().contains("code"));
        assertTrue(response.getRequiredData().contains("state"));

        ArgumentCaptor<String> userId = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<TrackActionRequest> request = ArgumentCaptor.forClass(TrackActionRequest.class);
        verify(client).trackAction(userId.capture(), eq("signUp"), request.capture());
        String generated = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
        assertEquals(userId.getValue(), generated);
        assertEquals(request.getValue().getEmail(), "alice@example.com");
        assertEquals(request.getValue().getPhoneNumber(), "+94770000000");

        // The portal resumes the flow with the code and state the executor put in the redirect URL.
        Map<String, String> query = query(request.getValue().getRedirectUrl());
        assertTrue(request.getValue().getRedirectUrl().startsWith(PORTAL_URL + "&"));
        assertEquals(query.get("state"), state);
        assertEquals(query.get("code"), context.getProperty(Executor.CONTEXT_PROP_CODE));
    }

    @Test
    public void testRegistrationCallbackCompletesAndStoresClaim() throws Exception {

        FlowExecutionContext context = registrationContext();
        challengeRequired(true);
        ExecutorResponse redirect = executor.execute(context);
        String generated = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
        String code = (String) context.getProperty(Executor.CONTEXT_PROP_CODE);

        when(client.getAction(generated, "signUp", "idem-1")).thenReturn(action("CHALLENGE_SUCCEEDED"));
        callback(context, code, redirect.getAdditionalInfo().get("state"));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertEquals(response.getUpdatedUserClaims().get(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM), generated);
        assertNull(context.getProperty(Executor.CONTEXT_PROP_STATE), "Challenge must be consumed");
        assertEquals(context.getProperty(Executor.CONTEXT_PROP_ENROLLED), true);
    }

    @Test
    public void testRetriedRegistrationReusesGeneratedUserId() throws Exception {

        FlowExecutionContext context = registrationContext();
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("ALLOW", null));

        ExecutorResponse first = executor.execute(context);
        ExecutorResponse second = executor.execute(context);

        Object firstId = first.getUpdatedUserClaims().get(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM);
        assertNotNull(firstId);
        assertEquals(second.getUpdatedUserClaims().get(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM), firstId);
    }

    @Test
    public void testRegistrationFailsWithoutClaim() throws Exception {

        claimConfigured = false;

        ExecutorResponse response = executor.execute(registrationContext());

        assertEquals(response.getResult(), "ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60018");
        verify(client, never()).trackAction(anyString(), anyString(), any());
    }

    @Test
    public void testCallbackWithWrongStateFails() throws Exception {

        FlowExecutionContext context = registrationContext();
        challengeRequired(true);
        executor.execute(context);
        String code = (String) context.getProperty(Executor.CONTEXT_PROP_CODE);

        callback(context, code, "forged-state");
        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60023");
        verify(client, never()).getAction(anyString(), anyString(), anyString());
    }

    @Test
    public void testCallbackCannotBeReplayed() throws Exception {

        FlowExecutionContext context = registrationContext();
        challengeRequired(true);
        ExecutorResponse redirect = executor.execute(context);
        String generated = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
        String code = (String) context.getProperty(Executor.CONTEXT_PROP_CODE);
        when(client.getAction(generated, "signUp", "idem-1")).thenReturn(action("CHALLENGE_SUCCEEDED"));
        callback(context, code, redirect.getAdditionalInfo().get("state"));
        assertEquals(executor.execute(context).getResult(), "COMPLETE");

        // With no pending challenge the same inputs start a new track, never a second completion from the result.
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("BLOCK", null));
        assertEquals(executor.execute(context).getResult(), "USER_ERROR");
    }

    @Test
    public void testChallengeNotSucceededFails() throws Exception {

        FlowExecutionContext context = registrationContext();
        challengeRequired(true);
        ExecutorResponse redirect = executor.execute(context);
        String generated = (String) context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID);
        when(client.getAction(generated, "signUp", "idem-1")).thenReturn(action("CHALLENGE_REQUIRED"));
        callback(context, (String) context.getProperty(Executor.CONTEXT_PROP_CODE),
                redirect.getAdditionalInfo().get("state"));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60010");
        assertNull(context.getProperty(Executor.CONTEXT_PROP_ENROLLED));
    }

    @Test
    public void testRecoveryUsesUserUuidAndRecoveryAction() throws Exception {

        challengeRequired(true);

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        ArgumentCaptor<TrackActionRequest> request = ArgumentCaptor.forClass(TrackActionRequest.class);
        verify(client).trackAction(eq(USER_UUID), eq("passwordRecovery"), request.capture());
        assertNull(request.getValue().getEmail(), "Contact details must not be sent in recovery");
    }

    @Test
    public void testRecoveryUsesMappedUserId() throws Exception {

        mappedUserId = "as-generated-at-signup";
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("ALLOW", null));

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "COMPLETE");
        assertNull(response.getUpdatedUserClaims(), "Existing users must not get a new mapping");
        verify(client).trackAction(eq("as-generated-at-signup"), eq("passwordRecovery"), any());
    }

    @Test
    public void testRecoveryRejectsUnenrolledUser() throws Exception {

        challengeRequired(false);

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60022");
    }

    @Test
    public void testRecoveryUnknownUserFailsGenerically() throws Exception {

        storeUserId = null;

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60021");
        verify(client, never()).trackAction(anyString(), anyString(), any());
    }

    @Test
    public void testBlockFails() throws Exception {

        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("BLOCK", null));

        ExecutorResponse response = executor.execute(registrationContext());

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), "AUTHSIGNAL-60007");
    }

    @Test
    public void testMissingPortalUrlFails() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setPortalUrl(null);

        assertEquals(executor.execute(context).getErrorCode(), "AUTHSIGNAL-60020");
    }

    @Test
    public void testRollbackDeletesEnrolledGeneratedUser() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID, "gen-1");
        context.setProperty(Executor.CONTEXT_PROP_ENROLLED, true);

        executor.rollback(context);

        verify(client).deleteUser("gen-1");
        assertNull(context.getProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID));
    }

    @Test
    public void testRollbackIgnoresDeleteFailureAndUnenrolledUser() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID, "gen-1");
        executor.rollback(context);
        verify(client, never()).deleteUser(anyString());

        context.setProperty(Executor.CONTEXT_PROP_GENERATED_USER_ID, "gen-2");
        context.setProperty(Executor.CONTEXT_PROP_ENROLLED, true);
        doThrow(new AuthsignalClientException("down")).when(client).deleteUser("gen-2");
        executor.rollback(context);
        assertFalse(context.getProperties().containsKey(Executor.CONTEXT_PROP_ENROLLED));
    }

    @Test
    public void testBuildRedirectUrl() {

        assertEquals(AuthsignalExecutor.buildRedirectUrl("https://is/accounts/register", "c", "s"),
                "https://is/accounts/register?code=c&state=s");
        assertEquals(AuthsignalExecutor.buildRedirectUrl("https://is/accounts/register?a=1#frag", "c", "s"),
                "https://is/accounts/register?a=1&code=c&state=s");
    }

    private FlowExecutionContext registrationContext() {

        FlowUser flowUser = new FlowUser();
        flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, "alice@example.com");
        flowUser.addClaim(AuthsignalConstants.MOBILE_CLAIM, "+94770000000");
        return context(Executor.REGISTRATION, flowUser);
    }

    private FlowExecutionContext recoveryContext() {

        FlowUser flowUser = new FlowUser();
        flowUser.setUsername("alice");
        flowUser.setUserStoreDomain("PRIMARY");
        flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, "alice@example.com");
        return context(Executor.PASSWORD_RECOVERY, flowUser);
    }

    private FlowExecutionContext context(String flowType, FlowUser flowUser) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setFlowType(flowType);
        context.setTenantDomain(TENANT);
        context.setPortalUrl(PORTAL_URL);
        context.setFlowUser(flowUser);
        context.setProperties(new HashMap<>());
        context.setUserInputData(new HashMap<>());
        return context;
    }

    private void callback(FlowExecutionContext context, String code, String state) {

        context.addUserInputData("code", code);
        context.addUserInputData("state", state);
    }

    private void challengeRequired(boolean enrolled) throws AuthsignalClientException {

        TrackActionResponse trackResponse = track("CHALLENGE_REQUIRED", CHALLENGE_URL);
        trackResponse.setIsEnrolled(enrolled);
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(trackResponse);
    }

    private static TrackActionResponse track(String state, String url) {

        TrackActionResponse response = new TrackActionResponse();
        response.setState(state);
        response.setUrl(url);
        response.setIdempotencyKey("idem-1");
        return response;
    }

    private static GetActionResponse action(String state) {

        GetActionResponse response = new GetActionResponse();
        response.setState(state);
        response.setVerificationMethod("PASSKEY");
        return response;
    }

    private static Map<String, String> query(String url) {

        Map<String, String> params = new HashMap<>();
        for (String pair : URI.create(url).getQuery().split("&")) {
            String[] kv = pair.split("=", 2);
            params.put(kv[0], kv.length > 1 ? kv[1] : "");
        }
        return params;
    }

    /**
     * Replaces the server runtime dependencies (tenant configuration, user store, HTTP client) with test doubles.
     */
    private class TestableExecutor extends AuthsignalExecutor {

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

            super.createClient(config);
            return client;
        }

        @Override
        protected boolean isUserIdClaimConfigured(String tenantDomain) {

            return claimConfigured;
        }

        @Override
        protected String getMappedUserId(String tenantDomain, String userStoreDomain, String username)
                throws UserStoreException {

            return mappedUserId;
        }

        @Override
        protected String getUserId(String tenantDomain, String userStoreDomain, String username) {

            return storeUserId;
        }
    }
}
