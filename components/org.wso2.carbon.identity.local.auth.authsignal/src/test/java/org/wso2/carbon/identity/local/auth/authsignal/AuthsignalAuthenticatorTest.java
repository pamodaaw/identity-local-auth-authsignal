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

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.ValidateChallengeResponse;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for {@link AuthsignalAuthenticator}.
 */
public class AuthsignalAuthenticatorTest {

    private static final String USER_ID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String CALLBACK_URL = "https://localhost:9443/commonauth?sessionDataKey=ctx-1";
    private static final String CHALLENGE_URL = "https://signin.authsignal.com/challenge";

    private AuthsignalClient client;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AuthenticationContext context;
    private AuthenticatedUser user;
    private Map<String, String> parameters;
    private Map<String, String> serverParameters;
    private IdentityGovernanceService governanceService;
    private TestableAuthenticator authenticator;
    private MockedStatic<IdentityUtil> identityUtil;
    // Authsignal user ID stored on the user (claim); null when the user has none.
    private String mappedUserId;
    private AuthenticationFailedException mappingFailure;

    @BeforeMethod
    public void setUp() {

        client = mock(AuthsignalClient.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);

        user = new AuthenticatedUser();
        user.setUserName("alice");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain("carbon.super");
        user.setUserId(USER_ID);
        user.setAuthenticatedSubjectIdentifier("alice");

        StepConfig step1 = new StepConfig();
        step1.setSubjectAttributeStep(true);
        step1.setAuthenticatedUser(user);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, step1);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        sequenceConfig.setApplicationConfig(new ApplicationConfig(new ServiceProvider(), "carbon.super"));

        context = new AuthenticationContext();
        context.setContextIdentifier("ctx-1");
        context.setTenantDomain("carbon.super");
        context.setSequenceConfig(sequenceConfig);
        // Initialized by the framework at runtime; used when publishing failed step attempts.
        context.initializeAnalyticsData();

        parameters = new HashMap<>();
        parameters.put(AuthsignalConstants.ConnectorConfig.SECRET_KEY, "secret");
        // Avoid user store lookups in unit tests.
        parameters.put(AuthsignalConstants.ConnectorConfig.SEND_EMAIL, "false");
        parameters.put(AuthsignalConstants.ConnectorConfig.SEND_PHONE_NUMBER, "false");

        serverParameters = new HashMap<>();
        // Tenant-wise configuration is served by the identity governance service.
        governanceService = mock(IdentityGovernanceService.class);
        try {
            when(governanceService.getConfiguration(any(String[].class), eq("carbon.super"))).thenAnswer(
                    invocation -> parameters.entrySet().stream().map(entry -> {
                        Property property = new Property();
                        property.setName(entry.getKey());
                        property.setValue(entry.getValue());
                        return property;
                    }).toArray(Property[]::new));
        } catch (IdentityGovernanceException e) {
            throw new IllegalStateException(e);
        }
        AuthsignalAuthenticatorDataHolder.setIdentityGovernanceService(governanceService);

        mappedUserId = null;
        mappingFailure = null;
        authenticator = new TestableAuthenticator();
        identityUtil = mockStatic(IdentityUtil.class);
        identityUtil.when(() -> IdentityUtil.getClientIpAddress(any())).thenReturn("203.0.113.10");
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        AuthsignalAuthenticatorDataHolder.setIdentityGovernanceService(null);
    }

    @Test
    public void testCanHandle() {

        assertFalse(authenticator.canHandle(request));
        when(request.getParameter("token")).thenReturn("tok");
        assertTrue(authenticator.canHandle(request));
    }

    @Test
    public void testChallengeRequiredRedirectsToPrebuiltUi() throws Exception {

        when(request.getHeader("User-Agent")).thenReturn("JUnit");
        when(client.trackAction(eq(USER_ID), eq("signIn"), any())).thenReturn(track("CHALLENGE_REQUIRED"));

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        verify(response).sendRedirect(CHALLENGE_URL);
        assertEquals(context.getProperty(AuthsignalConstants.CONTEXT_PROP_IDEMPOTENCY_KEY), "idem-1");
        assertEquals(context.getProperty(AuthsignalConstants.CONTEXT_PROP_AUTHSIGNAL_USER_ID), USER_ID);
        assertEquals(context.getCurrentAuthenticator(), AuthsignalConstants.AUTHENTICATOR_NAME);

        ArgumentCaptor<TrackActionRequest> captor = ArgumentCaptor.forClass(TrackActionRequest.class);
        verify(client).trackAction(eq(USER_ID), eq("signIn"), captor.capture());
        assertEquals(captor.getValue().getRedirectUrl(), CALLBACK_URL);
        assertEquals(captor.getValue().getIpAddress(), "203.0.113.10");
        assertEquals(captor.getValue().getUserAgent(), "JUnit");
        assertEquals(captor.getValue().getUsername(), "alice");
    }

    @Test
    public void testAllowCompletesWithoutChallenge() throws Exception {

        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("ALLOW"));

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertEquals(context.getSubject().getUserName(), "alice");
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testBlockFails() throws Exception {

        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("BLOCK"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_ACTION_BLOCKED.getCode());
        assertNull(context.getSubject());
    }

    @Test
    public void testReviewRequiredFailsByDefault() throws Exception {

        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("REVIEW_REQUIRED"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_ACTION_REVIEW_REQUIRED.getCode());
    }

    @Test
    public void testReviewRequiredAllowedWhenConfigured() throws Exception {

        parameters.put(AuthsignalConstants.ConnectorConfig.ALLOW_ON_REVIEW_REQUIRED, "true");
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("REVIEW_REQUIRED"));

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testNoPreviousStepFails() {

        context.getSequenceConfig().setStepMap(new HashMap<>());

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode());
    }

    @Test
    public void testMissingSecretFails() {

        parameters.remove(AuthsignalConstants.ConnectorConfig.SECRET_KEY);

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED.getCode());
    }

    @Test
    public void testUsernameIdentifier() throws Exception {

        AuthsignalConfig config = new AuthsignalConfig(Map.of(
                AuthsignalConstants.ConnectorConfig.USER_IDENTIFIER, "username"));
        assertEquals(authenticator.resolveAuthsignalUserId(user, config), "alice");

        user.setUserStoreDomain("LDAP");
        user.setTenantDomain("wso2.com");
        assertEquals(authenticator.resolveAuthsignalUserId(user, config), "LDAP/alice@wso2.com");
    }

    @Test
    public void testMappedUserIdTakesPrecedence() throws Exception {

        mappedUserId = "as-generated-at-signup";
        AuthsignalConfig config = new AuthsignalConfig(Map.of(
                AuthsignalConstants.ConnectorConfig.USER_IDENTIFIER, "username"));
        assertEquals(authenticator.resolveAuthsignalUserId(user, config), "as-generated-at-signup");
        assertEquals(authenticator.resolveAuthsignalUserId(user, new AuthsignalConfig(null)),
                "as-generated-at-signup");
    }

    @Test
    public void testMappingReadFailureFailsClosed() throws Exception {

        mappingFailure = new AuthenticationFailedException(
                AuthsignalConstants.ErrorMessages.ERROR_CODE_READING_USER_ID_MAPPING.getCode(), "boom");

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), "AUTHSIGNAL-60017");
        verify(client, never()).trackAction(anyString(), anyString(), any());
    }

    @Test
    public void testCallbackWithSuccessfulChallenge() throws Exception {

        challengeInitiated();
        when(client.validateChallenge("tok", USER_ID, "signIn"))
                .thenReturn(validate(true, "CHALLENGE_SUCCEEDED", USER_ID, "idem-1"));

        AuthenticatorFlowStatus status = authenticator.process(request, response, context);

        assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        assertNotNull(context.getSubject());
        assertEquals(context.getSubject().getUserName(), "alice");
        assertNull(context.getProperty(AuthsignalConstants.CONTEXT_PROP_IDEMPOTENCY_KEY));
    }

    @Test
    public void testCallbackWithFailedChallenge() throws Exception {

        challengeInitiated();
        when(client.validateChallenge(anyString(), anyString(), anyString()))
                .thenReturn(validate(false, "CHALLENGE_FAILED", USER_ID, "idem-1"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED.getCode());
    }

    @Test
    public void testCallbackWithTokenFromAnotherAction() throws Exception {

        challengeInitiated();
        when(client.validateChallenge(anyString(), anyString(), anyString()))
                .thenReturn(validate(true, "CHALLENGE_SUCCEEDED", USER_ID, "idem-other"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH.getCode());
    }

    @Test
    public void testTokenWithoutInitiatedChallengeStartsNewTrack() throws Exception {

        // A token on a request this flow did not challenge must never be validated.
        when(request.getParameter("token")).thenReturn("tok");
        when(client.trackAction(anyString(), anyString(), any())).thenReturn(track("CHALLENGE_REQUIRED"));

        assertEquals(authenticator.process(request, response, context), AuthenticatorFlowStatus.INCOMPLETE);
        verify(client, never()).validateChallenge(anyString(), any(), any());
    }

    @Test
    public void testConfigIsReadForTheRequestTenant() throws Exception {

        context.setTenantDomain("acme.com");
        user.setTenantDomain("acme.com");
        Property secret = new Property();
        secret.setName(AuthsignalConstants.ConnectorConfig.SECRET_KEY);
        secret.setValue("acme-secret");
        Property region = new Property();
        region.setName(AuthsignalConstants.ConnectorConfig.REGION);
        region.setValue("EU");
        when(governanceService.getConfiguration(any(String[].class), eq("acme.com")))
                .thenReturn(new Property[]{secret, region});

        AuthsignalConfig config = authenticator.getAuthsignalConfig(context);

        assertEquals(config.getSecretKey(), "acme-secret");
        assertEquals(config.getApiBaseUrl(), "https://eu.api.authsignal.com/v1");
        assertEquals(config.getActionCode(), "signIn");
    }

    @Test
    public void testDeploymentTomlParametersAreIgnored() throws Exception {

        // Configuration is tenant-wise only; authenticator parameters in deployment.toml must have no effect.
        parameters.put(AuthsignalConstants.ConnectorConfig.REGION, "au");
        serverParameters.put("ApiBaseUrl", "https://auth.example.com/v1");
        serverParameters.put("RequestTimeoutMillis", "1");

        AuthsignalConfig config = authenticator.getAuthsignalConfig(context);
        assertEquals(config.getApiBaseUrl(), "https://au.api.authsignal.com/v1");
        assertEquals(config.getRequestTimeoutMillis(), AuthsignalConstants.Defaults.REQUEST_TIMEOUT_MILLIS);
    }

    @Test
    public void testUnsupportedRegionFails() {

        // Tenants cannot supply a URL; an unknown region must not fall back to an arbitrary host.
        parameters.put(AuthsignalConstants.ConnectorConfig.REGION, "https://internal.example");

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_INVALID_REGION.getCode());
    }

    @Test
    public void testGovernanceErrorFails() throws Exception {

        when(governanceService.getConfiguration(any(String[].class), anyString()))
                .thenThrow(new IdentityGovernanceException("boom"));

        AuthenticationFailedException e = expectThrows(AuthenticationFailedException.class,
                () -> authenticator.process(request, response, context));
        assertEquals(e.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_READING_CONFIG.getCode());
    }

    private void challengeInitiated() {

        context.setProperty(AuthsignalConstants.CONTEXT_PROP_IDEMPOTENCY_KEY, "idem-1");
        context.setProperty(AuthsignalConstants.CONTEXT_PROP_AUTHSIGNAL_USER_ID, USER_ID);
        when(request.getParameter("token")).thenReturn("tok");
    }

    private static TrackActionResponse track(String state) {

        TrackActionResponse trackResponse = new TrackActionResponse();
        trackResponse.setState(state);
        trackResponse.setIdempotencyKey("idem-1");
        if ("CHALLENGE_REQUIRED".equals(state)) {
            trackResponse.setUrl(CHALLENGE_URL);
        }
        return trackResponse;
    }

    private static ValidateChallengeResponse validate(boolean valid, String state, String userId,
                                                      String idempotencyKey) {

        ValidateChallengeResponse validateResponse = new ValidateChallengeResponse();
        validateResponse.setIsValid(valid);
        validateResponse.setState(state);
        validateResponse.setUserId(userId);
        validateResponse.setIdempotencyKey(idempotencyKey);
        return validateResponse;
    }

    /**
     * Replaces the server runtime dependencies (URL builder, deployment.toml config, HTTP client) with test doubles.
     */
    private class TestableAuthenticator extends AuthsignalAuthenticator {

        private static final long serialVersionUID = 1L;

        @Override
        protected String buildCallbackUrl(AuthenticationContext context) {

            return CALLBACK_URL;
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthenticationFailedException {

            super.createClient(config);
            return client;
        }

        @Override
        protected String getMappedAuthsignalUserId(AuthenticatedUser user) throws AuthenticationFailedException {

            // The claim lookup requires the user store.
            if (mappingFailure != null) {
                throw mappingFailure;
            }
            return mappedUserId;
        }

        @Override
        protected AuthenticatorConfig getAuthenticatorConfig() {

            AuthenticatorConfig config = new AuthenticatorConfig();
            config.setParameterMap(serverParameters);
            return config;
        }

        @Override
        protected void publishAuthenticationStepAttempt(HttpServletRequest request, AuthenticationContext context,
                                                        org.wso2.carbon.identity.application.common.model.User user,
                                                        boolean success) {

            // Event publishing requires the OSGi runtime.
        }
    }
}
