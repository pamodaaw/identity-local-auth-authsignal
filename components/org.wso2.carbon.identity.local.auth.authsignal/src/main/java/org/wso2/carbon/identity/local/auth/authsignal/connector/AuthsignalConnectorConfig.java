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

package org.wso2.carbon.identity.local.auth.authsignal.connector;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Identity governance connector holding the tenant-wise configuration of the Authsignal authenticator.
 */
public class AuthsignalConnectorConfig implements IdentityConnectorConfig {

    @Override
    public String getName() {

        return ConnectorConfig.CONNECTOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return ConnectorConfig.CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return ConnectorConfig.CONNECTOR_CATEGORY;
    }

    @Override
    public String getSubCategory() {

        return ConnectorConfig.CONNECTOR_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {

        return ConnectorConfig.CONNECTOR_ORDER;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(ConnectorConfig.SECRET_KEY, "Secret key");
        nameMapping.put(ConnectorConfig.REGION, "Region");
        nameMapping.put(ConnectorConfig.ACTION_CODE, "Action code");
        nameMapping.put(ConnectorConfig.USER_IDENTIFIER, "User identifier");
        nameMapping.put(ConnectorConfig.SEND_EMAIL, "Send email address");
        nameMapping.put(ConnectorConfig.SEND_PHONE_NUMBER, "Send mobile number");
        nameMapping.put(ConnectorConfig.REDIRECT_TO_SETTINGS, "Redirect to authenticator settings");
        nameMapping.put(ConnectorConfig.ALLOW_ON_REVIEW_REQUIRED, "Allow sign-in on review required");
        nameMapping.put(ConnectorConfig.REGISTRATION_ACTION_CODE, "Registration action code");
        nameMapping.put(ConnectorConfig.RECOVERY_ACTION_CODE, "Password recovery action code");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(ConnectorConfig.SECRET_KEY,
                "Server API secret key of the Authsignal tenant");
        descriptionMapping.put(ConnectorConfig.REGION,
                "Region of the Authsignal tenant: us, eu, au, ca or uk");
        descriptionMapping.put(ConnectorConfig.ACTION_CODE,
                "Action code tracked on Authsignal. Rules are configured per action in the Authsignal Portal");
        descriptionMapping.put(ConnectorConfig.USER_IDENTIFIER,
                "Value used as the Authsignal user ID: userId (WSO2 user UUID) or username");
        descriptionMapping.put(ConnectorConfig.SEND_EMAIL,
                "Send the user's email address to Authsignal to enable email based verification");
        descriptionMapping.put(ConnectorConfig.SEND_PHONE_NUMBER,
                "Send the user's mobile number (E.164) to Authsignal to enable SMS based verification");
        descriptionMapping.put(ConnectorConfig.REDIRECT_TO_SETTINGS,
                "Show the user's Authsignal authenticator settings after the challenge");
        descriptionMapping.put(ConnectorConfig.ALLOW_ON_REVIEW_REQUIRED,
                "Continue the sign-in when Authsignal returns REVIEW_REQUIRED instead of failing it");
        descriptionMapping.put(ConnectorConfig.REGISTRATION_ACTION_CODE,
                "Action code tracked when Authsignal is used in a registration flow");
        descriptionMapping.put(ConnectorConfig.RECOVERY_ACTION_CODE,
                "Action code tracked when Authsignal is used in a password recovery flow");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        return ConnectorConfig.PROPERTY_NAMES.clone();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties properties = new Properties();
        properties.put(ConnectorConfig.SECRET_KEY, "");
        properties.put(ConnectorConfig.REGION, Defaults.REGION);
        properties.put(ConnectorConfig.ACTION_CODE, Defaults.ACTION_CODE);
        properties.put(ConnectorConfig.USER_IDENTIFIER, Defaults.USER_IDENTIFIER);
        properties.put(ConnectorConfig.SEND_EMAIL, String.valueOf(Defaults.SEND_EMAIL));
        properties.put(ConnectorConfig.SEND_PHONE_NUMBER, String.valueOf(Defaults.SEND_PHONE_NUMBER));
        properties.put(ConnectorConfig.REDIRECT_TO_SETTINGS, String.valueOf(Defaults.REDIRECT_TO_SETTINGS));
        properties.put(ConnectorConfig.ALLOW_ON_REVIEW_REQUIRED, String.valueOf(Defaults.ALLOW_ON_REVIEW_REQUIRED));
        properties.put(ConnectorConfig.REGISTRATION_ACTION_CODE, Defaults.REGISTRATION_ACTION_CODE);
        properties.put(ConnectorConfig.RECOVERY_ACTION_CODE, Defaults.RECOVERY_ACTION_CODE);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        return null;
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        return Collections.singletonList(ConnectorConfig.SECRET_KEY);
    }
}
