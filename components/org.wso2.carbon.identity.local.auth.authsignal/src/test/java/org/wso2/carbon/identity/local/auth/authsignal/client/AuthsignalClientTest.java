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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.GetActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.TrackActionResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.ValidateChallengeResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for {@link AuthsignalClient} against a local stub of the Authsignal Server API.
 */
public class AuthsignalClientTest {

    private static final String SECRET = "test-secret";

    private HttpServer server;
    private String baseUrl;
    private final AtomicReference<String> lastPath = new AtomicReference<>();
    private final AtomicReference<String> lastMethod = new AtomicReference<>();
    private final AtomicReference<String> lastAuthorization = new AtomicReference<>();
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private volatile int responseStatus;
    private volatile String responseBody;

    @BeforeMethod
    public void setUp() throws IOException {

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            lastPath.set(exchange.getRequestURI().getRawPath());
            lastMethod.set(exchange.getRequestMethod());
            lastAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(responseStatus, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/";
    }

    @AfterMethod
    public void tearDown() {

        server.stop(0);
    }

    @Test
    public void testTrackActionChallengeRequired() throws Exception {

        responseStatus = 200;
        responseBody = "{\"state\":\"CHALLENGE_REQUIRED\",\"url\":\"https://signin.authsignal.com/abc\","
                + "\"idempotencyKey\":\"idem-1\",\"isEnrolled\":true,\"ruleIds\":[]}";

        TrackActionResponse response = new AuthsignalClient(baseUrl, SECRET, 5000).trackAction("user 1/x",
                "signIn", new TrackActionRequest().setRedirectUrl("https://is/commonauth?sessionDataKey=k")
                        .setEmail("a@b.com"));

        assertEquals(response.getState(), "CHALLENGE_REQUIRED");
        assertEquals(response.getUrl(), "https://signin.authsignal.com/abc");
        assertEquals(response.getIdempotencyKey(), "idem-1");
        assertTrue(response.getIsEnrolled());
        assertEquals(lastPath.get(), "/v1/users/user%201%2Fx/actions/signIn");
        assertEquals(lastAuthorization.get(), "Basic " + Base64.getEncoder()
                .encodeToString((SECRET + ":").getBytes(StandardCharsets.UTF_8)));

        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("redirectUrl").getAsString(), "https://is/commonauth?sessionDataKey=k");
        assertEquals(body.get("email").getAsString(), "a@b.com");
        assertFalse(body.has("phoneNumber"), "Null fields must be omitted");
    }

    @Test
    public void testValidateChallenge() throws Exception {

        responseStatus = 200;
        responseBody = "{\"isValid\":true,\"state\":\"CHALLENGE_SUCCEEDED\",\"userId\":\"u1\",\"action\":\"signIn\","
                + "\"idempotencyKey\":\"idem-1\",\"verificationMethod\":\"PASSKEY\"}";

        ValidateChallengeResponse response = new AuthsignalClient(baseUrl, SECRET, 5000)
                .validateChallenge("tok", "u1", "signIn");

        assertTrue(response.isValid());
        assertEquals(response.getState(), "CHALLENGE_SUCCEEDED");
        assertEquals(response.getUserId(), "u1");
        assertEquals(response.getIdempotencyKey(), "idem-1");
        assertEquals(response.getVerificationMethod(), "PASSKEY");
        assertEquals(lastPath.get(), "/v1/validate");

        JsonObject body = JsonParser.parseString(lastBody.get()).getAsJsonObject();
        assertEquals(body.get("token").getAsString(), "tok");
        assertEquals(body.get("userId").getAsString(), "u1");
        assertEquals(body.get("action").getAsString(), "signIn");
    }

    @Test
    public void testGetAction() throws Exception {

        responseStatus = 200;
        responseBody = "{\"state\":\"CHALLENGE_SUCCEEDED\",\"verificationMethod\":\"PASSKEY\","
                + "\"createdAt\":\"2026-10-06T10:00:00Z\",\"ruleIds\":[]}";

        GetActionResponse response = new AuthsignalClient(baseUrl, SECRET, 5000)
                .getAction("user 1/x", "signUp", "idem/1");

        assertEquals(response.getState(), "CHALLENGE_SUCCEEDED");
        assertEquals(response.getVerificationMethod(), "PASSKEY");
        assertEquals(lastMethod.get(), "GET");
        assertEquals(lastPath.get(), "/v1/users/user%201%2Fx/actions/signUp/idem%2F1");
        assertEquals(lastBody.get(), "");
    }

    @Test
    public void testDeleteUser() throws Exception {

        responseStatus = 200;
        responseBody = "{\"success\":true}";

        new AuthsignalClient(baseUrl, SECRET, 5000).deleteUser("gen-1");

        assertEquals(lastMethod.get(), "DELETE");
        assertEquals(lastPath.get(), "/v1/users/gen-1");
    }

    @Test
    public void testErrorStatus() {

        responseStatus = 401;
        responseBody = "{\"error\":\"unauthorized\"}";

        AuthsignalClientException e = expectThrows(AuthsignalClientException.class,
                () -> new AuthsignalClient(baseUrl, SECRET, 5000).validateChallenge("tok", null, null));
        assertEquals(e.getStatusCode(), 401);
    }

    @Test
    public void testMalformedResponse() {

        responseStatus = 200;
        responseBody = "not json";

        expectThrows(AuthsignalClientException.class,
                () -> new AuthsignalClient(baseUrl, SECRET, 5000).validateChallenge("tok", null, null));
    }
}
