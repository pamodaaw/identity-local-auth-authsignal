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

package org.wso2.carbon.identity.local.auth.authsignal.model;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Region;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;

/**
 * Authsignal configuration of a tenant, built from the tenant's governance connector properties. There is no
 * server-wide (deployment.toml) configuration.
 */
public class AuthsignalConfig {

    private final String secretKey;
    private final String region;
    private final String actionCode;
    private final String userIdentifier;
    private final boolean sendEmail;
    private final boolean sendPhoneNumber;
    private final boolean redirectToSettings;
    private final boolean allowOnReviewRequired;
    private final String registrationActionCode;
    private final String recoveryActionCode;

    /**
     * @param tenantProperties Governance connector properties of the tenant, keyed by {@link ConnectorConfig} names.
     */
    public AuthsignalConfig(Map<String, String> tenantProperties) {

        Map<String, String> tenant = tenantProperties != null ? tenantProperties : Collections.emptyMap();

        this.secretKey = StringUtils.trimToNull(tenant.get(ConnectorConfig.SECRET_KEY));
        this.region = getString(tenant, ConnectorConfig.REGION, Defaults.REGION).toLowerCase(Locale.ROOT);
        this.actionCode = getString(tenant, ConnectorConfig.ACTION_CODE, Defaults.ACTION_CODE);
        this.userIdentifier = getString(tenant, ConnectorConfig.USER_IDENTIFIER, Defaults.USER_IDENTIFIER);
        this.sendEmail = getBoolean(tenant, ConnectorConfig.SEND_EMAIL, Defaults.SEND_EMAIL);
        this.sendPhoneNumber = getBoolean(tenant, ConnectorConfig.SEND_PHONE_NUMBER, Defaults.SEND_PHONE_NUMBER);
        this.redirectToSettings = getBoolean(tenant, ConnectorConfig.REDIRECT_TO_SETTINGS,
                Defaults.REDIRECT_TO_SETTINGS);
        this.allowOnReviewRequired = getBoolean(tenant, ConnectorConfig.ALLOW_ON_REVIEW_REQUIRED,
                Defaults.ALLOW_ON_REVIEW_REQUIRED);
        this.registrationActionCode = getString(tenant, ConnectorConfig.REGISTRATION_ACTION_CODE,
                Defaults.REGISTRATION_ACTION_CODE);
        this.recoveryActionCode = getString(tenant, ConnectorConfig.RECOVERY_ACTION_CODE,
                Defaults.RECOVERY_ACTION_CODE);
    }

    public String getSecretKey() {

        return secretKey;
    }

    public String getRegion() {

        return region;
    }

    /**
     * Resolve the Server API base URL from the tenant's region. Tenants cannot supply an arbitrary URL, so the server
     * only ever calls Authsignal's own hosts with the tenant's secret key and user data.
     *
     * @return The URL of the tenant's region, or {@code null} if the region is not supported.
     */
    public String getApiBaseUrl() {

        return Region.API_BASE_URLS.get(region);
    }

    public String getActionCode() {

        return actionCode;
    }

    public String getUserIdentifier() {

        return userIdentifier;
    }

    public boolean isSendEmail() {

        return sendEmail;
    }

    public boolean isSendPhoneNumber() {

        return sendPhoneNumber;
    }

    public boolean isRedirectToSettings() {

        return redirectToSettings;
    }

    public boolean isAllowOnReviewRequired() {

        return allowOnReviewRequired;
    }

    /**
     * @return Action code tracked when Authsignal is used in a registration flow.
     */
    public String getRegistrationActionCode() {

        return registrationActionCode;
    }

    /**
     * @return Action code tracked when Authsignal is used in a password recovery flow.
     */
    public String getRecoveryActionCode() {

        return recoveryActionCode;
    }

    /**
     * @return Timeout for each Authsignal API call. Fixed rather than tenant configurable, so that a tenant cannot hold
     * server threads for long periods.
     */
    public int getRequestTimeoutMillis() {

        return Defaults.REQUEST_TIMEOUT_MILLIS;
    }

    private static String getString(Map<String, String> params, String key, String defaultValue) {

        String value = StringUtils.trimToNull(params.get(key));
        return value != null ? value : defaultValue;
    }

    private static boolean getBoolean(Map<String, String> params, String key, boolean defaultValue) {

        String value = StringUtils.trimToNull(params.get(key));
        return value != null ? Boolean.parseBoolean(value) : defaultValue;
    }
}
