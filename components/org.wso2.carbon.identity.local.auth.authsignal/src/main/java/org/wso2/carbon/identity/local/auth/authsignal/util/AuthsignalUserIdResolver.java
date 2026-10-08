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
package org.wso2.carbon.identity.local.auth.authsignal.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Map;

/**
 * Resolves how a local WSO2 user maps to an Authsignal user ID. Shared by the authenticator and the flow executor
 * so that a user enrolled in one flow is recognised in every other flow.
 * <p>
 * The {@link AuthsignalConstants#AUTHSIGNAL_USER_ID_CLAIM} claim always takes precedence. It is set when the user
 * enrolled during self registration, before the WSO2 user UUID existed. Without it, the configured
 * {@link AuthsignalConstants.UserIdentifier} strategy applies.
 */
public final class AuthsignalUserIdResolver {

    private AuthsignalUserIdResolver() {

    }

    /**
     * Check whether the Authsignal user ID claim exists in the local claim dialect of the tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return True if the claim is configured.
     * @throws UserStoreException If the claim configuration cannot be read.
     */
    public static boolean isUserIdClaimConfigured(String tenantDomain) throws UserStoreException {

        UserRealm userRealm = getUserRealm(tenantDomain);
        return userRealm.getClaimManager().getClaim(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM) != null;
    }

    /**
     * Get the Authsignal user ID stored on the user.
     *
     * @param tenantDomain    Tenant domain of the user.
     * @param userStoreDomain User store domain of the user.
     * @param username        Username without the user store domain.
     * @return The mapped Authsignal user ID, or null if the claim is not configured or the user has no value.
     * @throws UserStoreException If the claim cannot be read. Callers must fail rather than fall back, otherwise an
     *                            enrolled user would look unenrolled to Authsignal and could enrol a new authenticator.
     */
    public static String getMappedUserId(String tenantDomain, String userStoreDomain, String username)
            throws UserStoreException {

        if (!isUserIdClaimConfigured(tenantDomain)) {
            return null;
        }
        UserStoreManager userStoreManager = getUserRealm(tenantDomain).getUserStoreManager();
        Map<String, String> claims = userStoreManager.getUserClaimValues(
                IdentityUtil.addDomainToName(username, userStoreDomain),
                new String[]{AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM}, null);
        return claims != null ? StringUtils.trimToNull(claims.get(AuthsignalConstants.AUTHSIGNAL_USER_ID_CLAIM))
                : null;
    }

    /**
     * Get the WSO2 user UUID of a user.
     *
     * @param tenantDomain    Tenant domain of the user.
     * @param userStoreDomain User store domain of the user.
     * @param username        Username without the user store domain.
     * @return User UUID, or null if the user does not exist.
     * @throws UserStoreException If the user store cannot be queried.
     */
    public static String getUserId(String tenantDomain, String userStoreDomain, String username)
            throws UserStoreException {

        UserStoreManager userStoreManager = getUserRealm(tenantDomain).getUserStoreManager();
        if (!(userStoreManager instanceof AbstractUserStoreManager)) {
            throw new UserStoreException("Unsupported user store manager: " + userStoreManager.getClass().getName());
        }
        return ((AbstractUserStoreManager) userStoreManager)
                .getUserIDFromUserName(IdentityUtil.addDomainToName(username, userStoreDomain));
    }

    /**
     * Build the Authsignal user ID used by the {@code username} strategy: {@code [DOMAIN/]username[@tenant]}, where the
     * primary user store domain and the super tenant are omitted.
     *
     * @param username        Username without the user store domain.
     * @param userStoreDomain User store domain of the user.
     * @param tenantDomain    Tenant domain of the user.
     * @return Qualified username.
     */
    public static String toQualifiedUsername(String username, String userStoreDomain, String tenantDomain) {

        String qualified = username;
        if (StringUtils.isNotBlank(userStoreDomain)
                && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(userStoreDomain)) {
            qualified = userStoreDomain + UserCoreConstants.DOMAIN_SEPARATOR + qualified;
        }
        if (StringUtils.isNotBlank(tenantDomain)
                && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {
            qualified = qualified + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
        }
        return qualified;
    }

    private static UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm = AuthsignalAuthenticatorDataHolder.getRealmService().getTenantUserRealm(tenantId);
        if (userRealm == null) {
            throw new UserStoreException("User realm is not available for the tenant: " + tenantDomain);
        }
        return userRealm;
    }
}
