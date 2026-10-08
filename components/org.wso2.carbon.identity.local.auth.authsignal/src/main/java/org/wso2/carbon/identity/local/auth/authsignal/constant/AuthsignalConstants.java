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

package org.wso2.carbon.identity.local.auth.authsignal.constant;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Constants used by the Authsignal authenticator.
 */
public class AuthsignalConstants {

    private AuthsignalConstants() {

    }

    public static final String AUTHENTICATOR_NAME = "AuthsignalAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Authsignal";
    public static final String AUTHENTICATOR_I18N_KEY = "authenticator.authsignal";

    // Request parameters.
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    // Authsignal appends this query parameter to the redirect URL once the pre-built UI challenge completes.
    public static final String TOKEN_PARAM = "token";
    public static final String USER_AGENT_HEADER = "User-Agent";

    // Authentication context property keys.
    public static final String CONTEXT_PROP_IDEMPOTENCY_KEY = "authsignal.idempotencyKey";
    public static final String CONTEXT_PROP_AUTHSIGNAL_USER_ID = "authsignal.userId";

    // Claim URIs used to pre-fill the user's contact details on Authsignal.
    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";

    // Maps a WSO2 user to the Authsignal user ID chosen when the user enrolled during self registration, before the
    // WSO2 user UUID existed. Takes precedence over the UserIdentifier strategy.
    public static final String AUTHSIGNAL_USER_ID_CLAIM = "http://wso2.org/claims/authsignalUserId";

    /**
     * Constants of the Authsignal flow executor, used in registration and password recovery flows.
     */
    public static class Executor {

        private Executor() {

        }

        public static final String EXECUTOR_NAME = "AuthsignalExecutor";
        public static final String EXECUTOR_DESCRIPTION =
                "Verify or enrol the user with Authsignal adaptive MFA during registration and password recovery.";

        // Flow types, as defined by org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.
        public static final String REGISTRATION = "REGISTRATION";
        public static final String INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";
        public static final String PASSWORD_RECOVERY = "PASSWORD_RECOVERY";

        // Inputs the hosted portal posts back after an external redirection.
        public static final String CODE_PARAM = "code";
        public static final String STATE_PARAM = "state";

        // Flow context property keys of a pending challenge.
        public static final String CONTEXT_PROP_USER_ID = "authsignal.flow.userId";
        public static final String CONTEXT_PROP_ACTION_CODE = "authsignal.flow.actionCode";
        public static final String CONTEXT_PROP_IDEMPOTENCY_KEY = "authsignal.flow.idempotencyKey";
        public static final String CONTEXT_PROP_STATE = "authsignal.flow.state";
        public static final String CONTEXT_PROP_CODE = "authsignal.flow.code";
        // Authsignal user ID generated in this flow. Kept across retries so a user is never enrolled twice.
        public static final String CONTEXT_PROP_GENERATED_USER_ID = "authsignal.flow.generatedUserId";
        // Set once a challenge for the generated user ID succeeded, so rollback knows there is something to remove.
        public static final String CONTEXT_PROP_ENROLLED = "authsignal.flow.enrolled";
    }

    /**
     * Tenant-wise configuration, exposed as an identity governance connector. Tenant admins manage it through the
     * identity-governance REST API / Console, and it is stored as resident IdP properties of the tenant.
     */
    public static class ConnectorConfig {

        private ConnectorConfig() {

        }

        public static final String CONNECTOR_NAME = "authsignal-authenticator";
        public static final String CONNECTOR_FRIENDLY_NAME = "Authsignal";
        public static final String CONNECTOR_CATEGORY = "Multi Factor Authenticators";
        public static final String CONNECTOR_SUB_CATEGORY = "DEFAULT";
        public static final int CONNECTOR_ORDER = 0;

        // The __secret__ prefix renders the field as a password input; the property is also marked confidential so
        // the governance REST API masks it in responses.
        public static final String SECRET_KEY = "__secret__.Authsignal.SecretKey";
        public static final String REGION = "Authsignal.Region";
        public static final String ACTION_CODE = "Authsignal.ActionCode";
        public static final String USER_IDENTIFIER = "Authsignal.UserIdentifier";
        public static final String SEND_EMAIL = "Authsignal.SendEmail";
        public static final String SEND_PHONE_NUMBER = "Authsignal.SendPhoneNumber";
        public static final String REDIRECT_TO_SETTINGS = "Authsignal.RedirectToSettings";
        public static final String ALLOW_ON_REVIEW_REQUIRED = "Authsignal.AllowOnReviewRequired";
        public static final String REGISTRATION_ACTION_CODE = "Authsignal.RegistrationActionCode";
        public static final String RECOVERY_ACTION_CODE = "Authsignal.RecoveryActionCode";

        public static final String[] PROPERTY_NAMES = {SECRET_KEY, REGION, ACTION_CODE, USER_IDENTIFIER, SEND_EMAIL,
                SEND_PHONE_NUMBER, REDIRECT_TO_SETTINGS, ALLOW_ON_REVIEW_REQUIRED, REGISTRATION_ACTION_CODE,
                RECOVERY_ACTION_CODE};
    }


    /**
     * Default values for the configuration.
     */
    public static class Defaults {

        private Defaults() {

        }

        public static final String REGION = Region.US;
        public static final String ACTION_CODE = "signIn";
        public static final String USER_IDENTIFIER = UserIdentifier.USER_ID;
        public static final boolean SEND_EMAIL = true;
        public static final boolean SEND_PHONE_NUMBER = true;
        public static final boolean REDIRECT_TO_SETTINGS = false;
        public static final boolean ALLOW_ON_REVIEW_REQUIRED = false;
        public static final String REGISTRATION_ACTION_CODE = "signUp";
        public static final String RECOVERY_ACTION_CODE = "passwordRecovery";
        public static final int REQUEST_TIMEOUT_MILLIS = 10000;
    }

    /**
     * Authsignal regions and their Server API base URLs.
     * See https://docs.authsignal.com/api-reference/server-api/overview
     */
    public static class Region {

        private Region() {

        }

        public static final String US = "us";
        public static final String EU = "eu";
        public static final String AU = "au";
        public static final String CA = "ca";
        public static final String UK = "uk";

        public static final Map<String, String> API_BASE_URLS;

        static {
            Map<String, String> urls = new LinkedHashMap<>();
            urls.put(US, "https://api.authsignal.com/v1");
            urls.put(EU, "https://eu.api.authsignal.com/v1");
            urls.put(AU, "https://au.api.authsignal.com/v1");
            urls.put(CA, "https://ca.api.authsignal.com/v1");
            urls.put(UK, "https://uk.api.authsignal.com/v1");
            API_BASE_URLS = Collections.unmodifiableMap(urls);
        }
    }

    /**
     * Supported strategies for mapping a WSO2 user to an Authsignal user ID.
     */
    public static class UserIdentifier {

        private UserIdentifier() {

        }

        // The immutable WSO2 user UUID (recommended).
        public static final String USER_ID = "userId";
        // The tenant-qualified, user store domain aware username.
        public static final String USERNAME = "username";
    }

    /**
     * Authsignal action states.
     * See https://docs.authsignal.com/api-reference/server-api/track-action
     */
    public static class ActionState {

        private ActionState() {

        }

        public static final String ALLOW = "ALLOW";
        public static final String BLOCK = "BLOCK";
        public static final String CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED";
        public static final String CHALLENGE_SUCCEEDED = "CHALLENGE_SUCCEEDED";
        public static final String CHALLENGE_FAILED = "CHALLENGE_FAILED";
        public static final String REVIEW_REQUIRED = "REVIEW_REQUIRED";
        public static final String REVIEW_SUCCEEDED = "REVIEW_SUCCEEDED";
        public static final String REVIEW_FAILED = "REVIEW_FAILED";
    }

    /**
     * Error messages of the Authsignal authenticator.
     */
    public enum ErrorMessages {

        ERROR_CODE_NO_AUTHENTICATED_USER("AUTHSIGNAL-60001",
                "No authenticated user found. Authsignal must be configured after a step that identifies the user."),
        ERROR_CODE_SECRET_KEY_NOT_CONFIGURED("AUTHSIGNAL-60002",
                "Authsignal secret key is not configured for the tenant."),
        ERROR_CODE_INVALID_USER_IDENTIFIER("AUTHSIGNAL-60003",
                "Unsupported Authsignal user identifier configuration: %s."),
        ERROR_CODE_RESOLVING_USER_ID("AUTHSIGNAL-60004",
                "Error while resolving the Authsignal user ID for the authenticated user."),
        ERROR_CODE_TRACK_ACTION_FAILED("AUTHSIGNAL-60005",
                "Error while tracking the action on Authsignal."),
        ERROR_CODE_VALIDATE_CHALLENGE_FAILED("AUTHSIGNAL-60006",
                "Error while validating the challenge on Authsignal."),
        ERROR_CODE_ACTION_BLOCKED("AUTHSIGNAL-60007",
                "Authsignal blocked the sign-in attempt."),
        ERROR_CODE_ACTION_REVIEW_REQUIRED("AUTHSIGNAL-60008",
                "Authsignal flagged the sign-in attempt for review."),
        ERROR_CODE_UNEXPECTED_ACTION_STATE("AUTHSIGNAL-60009",
                "Unexpected action state returned by Authsignal: %s."),
        ERROR_CODE_CHALLENGE_NOT_SUCCEEDED("AUTHSIGNAL-60010",
                "The Authsignal challenge was not completed successfully."),
        ERROR_CODE_CHALLENGE_MISMATCH("AUTHSIGNAL-60011",
                "The Authsignal challenge result does not belong to the current authentication flow."),
        ERROR_CODE_BUILDING_CALLBACK_URL("AUTHSIGNAL-60012",
                "Error while building the Authsignal callback URL."),
        ERROR_CODE_REDIRECTING("AUTHSIGNAL-60013",
                "Error while redirecting the user to the Authsignal challenge."),
        ERROR_CODE_MISSING_TOKEN("AUTHSIGNAL-60014",
                "The Authsignal result token is missing in the request."),
        ERROR_CODE_INVALID_REGION("AUTHSIGNAL-60015",
                "Unsupported Authsignal region: %s."),
        ERROR_CODE_READING_CONFIG("AUTHSIGNAL-60016",
                "Error while reading the Authsignal configuration of the tenant."),
        ERROR_CODE_READING_USER_ID_MAPPING("AUTHSIGNAL-60017",
                "Error while reading the Authsignal user ID mapping of the user."),
        ERROR_CODE_USER_ID_CLAIM_NOT_CONFIGURED("AUTHSIGNAL-60018",
                "The claim " + AUTHSIGNAL_USER_ID_CLAIM + " is not configured in the tenant."),
        ERROR_CODE_UNSUPPORTED_FLOW_TYPE("AUTHSIGNAL-60019",
                "Authsignal is not supported in the flow type: %s."),
        ERROR_CODE_PORTAL_URL_NOT_FOUND("AUTHSIGNAL-60020",
                "The portal URL to return to after the Authsignal challenge is not available in the flow."),
        ERROR_CODE_USER_NOT_IDENTIFIED("AUTHSIGNAL-60021",
                "The user could not be verified."),
        ERROR_CODE_USER_NOT_ENROLLED("AUTHSIGNAL-60022",
                "The user could not be verified."),
        ERROR_CODE_INVALID_CALLBACK("AUTHSIGNAL-60023",
                "The Authsignal challenge result does not belong to the current flow."),
        ERROR_CODE_GET_ACTION_FAILED("AUTHSIGNAL-60024",
                "Error while retrieving the action result from Authsignal.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
