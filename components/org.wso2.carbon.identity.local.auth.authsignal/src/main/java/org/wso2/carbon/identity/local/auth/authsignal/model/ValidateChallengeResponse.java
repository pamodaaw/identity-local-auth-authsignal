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

/**
 * Relevant fields of the Authsignal validate challenge API response.
 */
public class ValidateChallengeResponse {

    private Boolean isValid;
    private String state;
    private String userId;
    private String action;
    private String idempotencyKey;
    private String verificationMethod;

    public boolean isValid() {

        return Boolean.TRUE.equals(isValid);
    }

    public void setIsValid(Boolean isValid) {

        this.isValid = isValid;
    }

    public String getState() {

        return state;
    }

    public void setState(String state) {

        this.state = state;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    public String getAction() {

        return action;
    }

    public void setAction(String action) {

        this.action = action;
    }

    public String getIdempotencyKey() {

        return idempotencyKey;
    }

    public void setIdempotencyKey(String idempotencyKey) {

        this.idempotencyKey = idempotencyKey;
    }

    public String getVerificationMethod() {

        return verificationMethod;
    }

    public void setVerificationMethod(String verificationMethod) {

        this.verificationMethod = verificationMethod;
    }
}
