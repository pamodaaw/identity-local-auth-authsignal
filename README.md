# Authsignal Authenticator for WSO2 Identity Server

A custom **local authenticator** that adds [Authsignal](https://www.authsignal.com) adaptive MFA to a self-hosted
WSO2 Identity Server login flow. It is the on-prem equivalent of Authsignal's
[WSO2 Identity Platform integration](https://docs.authsignal.com/integrations/wso2-identity-platform): after the user
is identified, Authsignal decides whether to allow, block, or challenge the sign-in, and challenges run in Authsignal's
[pre-built UI](https://docs.authsignal.com/implementation-options/prebuilt-ui/overview).

## How it works

```text
Step 1 (e.g. Username & Password) identifies the user
        │
        ▼
AuthsignalAuthenticator ── POST /v1/users/{userId}/actions/{actionCode} ──▶ Authsignal rules engine
        │                    redirectUrl = https://<is>/commonauth?sessionDataKey=<ctx>
        │
        ├─ ALLOW              → step completes, no prompt
        ├─ BLOCK              → login fails (AUTHSIGNAL-60007)
        ├─ REVIEW_REQUIRED    → login fails (AUTHSIGNAL-60008), unless AllowOnReviewRequired = true
        └─ CHALLENGE_REQUIRED → 302 to Authsignal pre-built UI (passkey, TOTP, SMS, email OTP, …)
                                       │
                                       ▼
                     302 back to /commonauth?sessionDataKey=<ctx>&token=<jwt>
                                       │
AuthsignalAuthenticator ── POST /v1/validate {token, userId, action} ──▶ Authsignal
        │
        └─ step completes only if isValid, state = CHALLENGE_SUCCEEDED, and the userId and
           idempotencyKey match the action tracked in this authentication context
```

The secret key never leaves the server. Matching the `idempotencyKey` binds the returned token to the action this
login tracked. A token from another session or action is rejected (AUTHSIGNAL-60011). A `token` parameter is ignored
unless this flow started a challenge.

## Build

Requires JDK 11+ and Maven 3.6+.

```bash
mvn clean install
```

The OSGi bundle is created at
`components/org.wso2.carbon.identity.local.auth.authsignal/target/org.wso2.carbon.identity.local.auth.authsignal-1.0.0-SNAPSHOT.jar`.

## Deploy

1. Copy the JAR to `<IS_HOME>/repository/components/dropins/` and restart the server. Nothing needs to be added to
   `deployment.toml`: all configuration is tenant-wise.
2. Configure Authsignal for each tenant (see below).
3. In the Console, open the application > **Login Flow**. Add **Authsignal** as the **second** step, after a step that
   identifies the user (Username & Password, Identifier First, or a federated IdP).

## Configuration (tenant-wise)

Each tenant (or Asgardeo organization) has its own Authsignal configuration. It is an identity governance connector
(`authsignal-authenticator`, category *Multi Factor Authenticators*) and is stored with the tenant's resident IdP.
There are no server-wide settings.

Tenant admins manage it with the identity-governance REST API. The path IDs are the base64url forms of the category
and connector names:

```bash
curl -X PATCH \
  "https://<host>/t/<tenant-domain>/api/server/v1/identity-governance/TXVsdGkgRmFjdG9yIEF1dGhlbnRpY2F0b3Jz/connectors/YXV0aHNpZ25hbC1hdXRoZW50aWNhdG9y" \
  -H "Authorization: Bearer <token with the identity governance update scope>" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "UPDATE",
    "properties": [
      { "name": "__secret__.Authsignal.SecretKey", "value": "<Authsignal API key>" },
      { "name": "Authsignal.Region", "value": "us" }
    ]
  }'
```

Send a `GET` to the same URL to read the configuration. The secret key is a confidential property, so the API
masks it in responses. Only send the properties you want to change; the others keep their defaults.

| Property | Default | Description |
|---|---|---|
| `__secret__.Authsignal.SecretKey` | – (required) | Authsignal Server API key (Authsignal Portal > Settings > API keys). |
| `Authsignal.Region` | `us` | Region of the Authsignal tenant: `us`, `eu`, `au`, `ca` or `uk`. Match it to the API Host shown in the Authsignal Portal. Tenants pick a region rather than a URL, so the server only calls Authsignal's own hosts. |
| `Authsignal.ActionCode` | `signIn` | Action tracked on Authsignal at sign-in. Configure rules for it in the Authsignal Portal. |
| `Authsignal.UserIdentifier` | `userId` | Which value becomes the Authsignal user ID. `userId` is the WSO2 user UUID, which stays stable across renames. `username` is `[DOMAIN/]username[@tenant]`, where the primary domain and `carbon.super` are omitted. Federated users always use their subject identifier. |
| `Authsignal.SendEmail` / `Authsignal.SendPhoneNumber` | `true` | Send the `emailaddress` and E.164 `mobile` claims so Authsignal can offer email / SMS methods. |
| `Authsignal.RedirectToSettings` | `false` | Show Authsignal authenticator settings after the challenge. |
| `Authsignal.AllowOnReviewRequired` | `false` | Treat `REVIEW_REQUIRED` as allow instead of failing the login. |
| `Authsignal.RegistrationActionCode` | `signUp` | Action tracked when Authsignal runs in a registration or invited-user registration flow. |
| `Authsignal.RecoveryActionCode` | `passwordRecovery` | Action tracked when Authsignal runs in a password recovery flow. |

Each Authsignal API call has a fixed 10 second timeout. It is not configurable, so that one tenant cannot hold server
threads for long periods.

### Conditional MFA with adaptive scripts

You can use the authenticator from an adaptive script like any other step, for example:

```js
var onLoginRequest = function (context) {
    executeStep(1, {
        onSuccess: function (context) {
            executeStep(2); // step 2 = Authsignal
        }
    });
};
```

Authsignal's own rules decide whether the user is challenged. Most risk logic therefore belongs in the Authsignal
Portal, not in the script.

## Registration and password recovery flows

The bundle also registers **`AuthsignalExecutor`**, which adds Authsignal to the flows built in Console > **Flows**:
self registration, invited-user registration and password recovery. It works with the hosted portal (`/accounts`).

### How the user is mapped

During registration the WSO2 user UUID does not exist yet when the executor runs. The executor therefore
generates a random UUID as the Authsignal user ID and enrols the user under it. On success it returns the ID as the
`http://wso2.org/claims/authsignalUserId` claim, which is saved when the user is created. The authenticator and the
executor always use this claim when it is set, and otherwise fall back to `UserIdentifier`. Authenticators enrolled
at signup are therefore used at sign-in, and existing users are unaffected.

If the flow fails after enrolment (for example, user creation fails), the executor deletes the Authsignal user it
created (best effort).

### Challenge round trip

```text
AuthsignalExecutor ── POST /users/{id}/actions/{signUp|passwordRecovery}, redirectUrl = <portal>?code=<nonce>&state=<nonce>
        ├─ ALLOW / BLOCK / REVIEW_REQUIRED → continue / fail, as for sign-in
        └─ CHALLENGE_REQUIRED → portal redirects to the Authsignal pre-built UI
                                      │
                    302 back to <portal>?code=<nonce>&state=<nonce>&token=<jwt>  (token ignored)
                                      │
portal resumes the flow with {code, state}
AuthsignalExecutor ── checks both nonces (one-time), then GET /users/{id}/actions/{action}/{idempotencyKey}
        └─ continues only if the action is CHALLENGE_SUCCEEDED
```

The hosted portal resumes a flow only with `code` + `state`, so the Authsignal `token` is not used. The result is read
server to server with the user ID, action and idempotency key kept in the flow context.

### Setup

1. Create the local claim `http://wso2.org/claims/authsignalUserId` (Console > User Attributes & Stores >
   Attributes). Map it to a user store attribute and do not display it on the user profile. Registration flows fail
   with AUTHSIGNAL-60018 until it exists.
2. In the Authsignal Portal, add rules for the `signUp` and `passwordRecovery` actions. For enrolment at signup, make
   `signUp` always challenge: the pre-built UI then lets the new user enrol a passkey or other authenticator.
3. In Console > **Flows**, add the **Authsignal** node:
   - **Registration:** after the attribute collection form and **before** the user onboarding step.
   - **Password recovery:** after the user is identified and before the password reset step.

   Like Email OTP, the node needs no connection. The Console's password recovery check accepts only Email OTP,
   SMS OTP, Magic Link or authentication executors (which require a connection) as the recovery factor, so keep one
   of those before the reset step and use Authsignal as an extra check.

In password recovery only users who are already enrolled may continue (AUTHSIGNAL-60022). Otherwise whoever started
the recovery could enrol their own authenticator in the pre-built UI. Contact details are not sent to Authsignal in
recovery. Unknown users get a generic error.

## Troubleshooting

Enable debug logs in `<IS_HOME>/repository/conf/log4j2.properties`:

```properties
logger.authsignal.name = org.wso2.carbon.identity.local.auth.authsignal
logger.authsignal.level = DEBUG
```

| Error code | Meaning |
|---|---|
| AUTHSIGNAL-60001 | No user identified before the Authsignal step. Move it to step 2 or later. |
| AUTHSIGNAL-60002 | The tenant has not set `__secret__.Authsignal.SecretKey`. |
| AUTHSIGNAL-60005 / 60006 | Authsignal API call failed. Check the tenant's secret key and region, and network egress. |
| AUTHSIGNAL-60015 | The tenant's `Authsignal.Region` is not one of `us`, `eu`, `au`, `ca`, `uk`. |
| AUTHSIGNAL-60016 | The tenant's Authsignal configuration could not be read. |
| AUTHSIGNAL-60007 / 60008 | Authsignal returned BLOCK / REVIEW_REQUIRED. |
| AUTHSIGNAL-60010 | The user failed or abandoned the challenge. |
| AUTHSIGNAL-60011 | The token does not belong to the action tracked in this login. |
| AUTHSIGNAL-60017 | The `authsignalUserId` claim could not be read. The step fails instead of falling back to another ID. |
| AUTHSIGNAL-60018 | Registration flow: the `authsignalUserId` claim is not configured in the tenant. |
| AUTHSIGNAL-60020 | The flow has no portal URL to return to after the challenge. |
| AUTHSIGNAL-60021 / 60022 | Password recovery: the user does not exist / has no Authsignal authenticator enrolled. |
| AUTHSIGNAL-60023 | The `code` / `state` returned to the flow do not match (forged, or a reused link). |
| AUTHSIGNAL-60024 | Reading the action result from Authsignal failed. |

## Limitations / future work

- Browser redirect flows only. App-native (API-based) authentication is not implemented
  (`isAPIBasedAuthenticationSupported()` returns `false`).
- Second-factor only. Using it as a passwordless first factor would need an identifier-first step or the client-side
  passkey flow from [authsignal-wso2-authenticator](https://github.com/authsignal-examples/authsignal-wso2-authenticator).
- The secret key is masked by the REST API but stored unencrypted with the tenant's resident IdP properties, as with
  other governance connectors. Encrypting it at rest would need WSO2's secret management service.
- The connector may not appear as a form in the Console, which has dedicated screens for known connectors. The REST
  API always works.
