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
 * Request body of the Authsignal track action API.
 * Null fields are omitted from the serialized JSON.
 */
public class TrackActionRequest {

    private String redirectUrl;
    private String email;
    private String phoneNumber;
    private String username;
    private String ipAddress;
    private String userAgent;
    private Boolean redirectToSettings;

    public String getRedirectUrl() {

        return redirectUrl;
    }

    public TrackActionRequest setRedirectUrl(String redirectUrl) {

        this.redirectUrl = redirectUrl;
        return this;
    }

    public String getEmail() {

        return email;
    }

    public TrackActionRequest setEmail(String email) {

        this.email = email;
        return this;
    }

    public String getPhoneNumber() {

        return phoneNumber;
    }

    public TrackActionRequest setPhoneNumber(String phoneNumber) {

        this.phoneNumber = phoneNumber;
        return this;
    }

    public String getUsername() {

        return username;
    }

    public TrackActionRequest setUsername(String username) {

        this.username = username;
        return this;
    }

    public String getIpAddress() {

        return ipAddress;
    }

    public TrackActionRequest setIpAddress(String ipAddress) {

        this.ipAddress = ipAddress;
        return this;
    }

    public String getUserAgent() {

        return userAgent;
    }

    public TrackActionRequest setUserAgent(String userAgent) {

        this.userAgent = userAgent;
        return this;
    }

    public Boolean getRedirectToSettings() {

        return redirectToSettings;
    }

    public TrackActionRequest setRedirectToSettings(Boolean redirectToSettings) {

        this.redirectToSettings = redirectToSettings;
        return this;
    }
}
