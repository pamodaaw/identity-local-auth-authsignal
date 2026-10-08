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

package org.wso2.carbon.identity.local.auth.authsignal.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.GetActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.ValidateChallengeResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * Minimal client for the Authsignal Server API.
 * See https://docs.authsignal.com/api-reference/server-api/overview
 */
public class AuthsignalClient {

    private static final Log LOG = LogFactory.getLog(AuthsignalClient.class);
    private static final Gson GSON = new Gson();
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    // Shared across instances; java.net.http.HttpClient is thread safe and pools connections.
    private static final HttpClient DEFAULT_HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final HttpClient httpClient;
    private final String baseUrl;
    private final String authorizationHeader;
    private final Duration requestTimeout;

    public AuthsignalClient(String baseUrl, String secretKey, int requestTimeoutMillis) {

        this(DEFAULT_HTTP_CLIENT, baseUrl, secretKey, requestTimeoutMillis);
    }

    AuthsignalClient(HttpClient httpClient, String baseUrl, String secretKey, int requestTimeoutMillis) {

        this.httpClient = httpClient;
        this.baseUrl = StringUtils.removeEnd(baseUrl.trim(), "/");
        // Authsignal uses HTTP basic auth with the secret key as the username and an empty password.
        this.authorizationHeader = "Basic " + Base64.getEncoder()
                .encodeToString((secretKey + ":").getBytes(StandardCharsets.UTF_8));
        this.requestTimeout = Duration.ofMillis(requestTimeoutMillis);
    }

    /**
     * Track an action for a user. Authsignal evaluates its rules and returns the resulting state, along with a
     * pre-built UI URL when a challenge is required.
     *
     * @param userId  Authsignal user ID.
     * @param action  Action code.
     * @param request Additional action attributes.
     * @return Track action response.
     * @throws AuthsignalClientException If the API call fails.
     */
    public TrackActionResponse trackAction(String userId, String action, TrackActionRequest request)
            throws AuthsignalClientException {

        String path = "/users/" + encodePathSegment(userId) + "/actions/" + encodePathSegment(action);
        return post(path, GSON.toJson(request), TrackActionResponse.class);
    }

    /**
     * Validate the token Authsignal appended to the redirect URL after the pre-built UI challenge.
     *
     * @param token  Token received on the redirect.
     * @param userId Expected Authsignal user ID. Authsignal rejects the token if it belongs to another user.
     * @param action Expected action code.
     * @return Validate challenge response.
     * @throws AuthsignalClientException If the API call fails.
     */
    public ValidateChallengeResponse validateChallenge(String token, String userId, String action)
            throws AuthsignalClientException {

        JsonObject body = new JsonObject();
        body.addProperty("token", token);
        if (StringUtils.isNotBlank(userId)) {
            body.addProperty("userId", userId);
        }
        if (StringUtils.isNotBlank(action)) {
            body.addProperty("action", action);
        }
        return post("/validate", body.toString(), ValidateChallengeResponse.class);
    }

    /**
     * Get the current state of a tracked action. Used where the redirect back from the pre-built UI cannot carry the
     * token, so the result is read server to server using the action identifiers kept on the server.
     *
     * @param userId         Authsignal user ID.
     * @param action         Action code.
     * @param idempotencyKey Idempotency key returned when the action was tracked.
     * @return Get action response.
     * @throws AuthsignalClientException If the API call fails.
     */
    public GetActionResponse getAction(String userId, String action, String idempotencyKey)
            throws AuthsignalClientException {

        String path = "/users/" + encodePathSegment(userId) + "/actions/" + encodePathSegment(action) + "/"
                + encodePathSegment(idempotencyKey);
        return send("GET", path, null, GetActionResponse.class);
    }

    /**
     * Delete a user and the user's authenticators on Authsignal.
     *
     * @param userId Authsignal user ID.
     * @throws AuthsignalClientException If the API call fails.
     */
    public void deleteUser(String userId) throws AuthsignalClientException {

        send("DELETE", "/users/" + encodePathSegment(userId), null, JsonObject.class);
    }

    private <T> T post(String path, String jsonBody, Class<T> responseType) throws AuthsignalClientException {

        return send("POST", path, jsonBody, responseType);
    }

    private <T> T send(String method, String path, String jsonBody, Class<T> responseType)
            throws AuthsignalClientException {

        HttpRequest httpRequest;
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(requestTimeout)
                    .header("Authorization", authorizationHeader)
                    .header("Accept", "application/json");
            if (jsonBody != null) {
                builder.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
            } else {
                builder.method(method, HttpRequest.BodyPublishers.noBody());
            }
            httpRequest = builder.build();
        } catch (IllegalArgumentException e) {
            throw new AuthsignalClientException("Invalid Authsignal API URL: " + baseUrl, e);
        }

        HttpResponse<String> httpResponse;
        try {
            httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthsignalClientException("Interrupted while calling the Authsignal API.", e);
        } catch (IOException e) {
            throw new AuthsignalClientException("Error while calling the Authsignal API.", e);
        }

        int status = httpResponse.statusCode();
        if (status < 200 || status >= 300) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal API " + path.replaceAll("/users/[^/]+", "/users/***") + " returned HTTP "
                        + status + ": " + httpResponse.body());
            }
            throw new AuthsignalClientException("Authsignal API returned HTTP " + status + ".", status);
        }

        try {
            T result = GSON.fromJson(httpResponse.body(), responseType);
            if (result == null) {
                throw new AuthsignalClientException("Empty response received from the Authsignal API.", status);
            }
            return result;
        } catch (JsonParseException e) {
            throw new AuthsignalClientException("Invalid response received from the Authsignal API.", e);
        }
    }

    private static String encodePathSegment(String value) {

        // URLEncoder does form encoding; spaces must be %20 inside a path segment.
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
