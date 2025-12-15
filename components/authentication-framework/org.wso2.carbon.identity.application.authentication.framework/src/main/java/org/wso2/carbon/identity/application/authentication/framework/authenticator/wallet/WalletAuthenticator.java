/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.authenticator.wallet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Wallet Authenticator for OpenID4VP-compliant digital wallet authentication.
 * This authenticator enables users to log in using verifiable credentials from their digital wallets.
 */
public class WalletAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(WalletAuthenticator.class);
    private static final long serialVersionUID = 7342280360016122360L;

    // Authenticator configuration constants.
    private static final String AUTHENTICATOR_NAME = "WalletAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet Login";

    // OpenID4VP protocol constants.
    private static final String VP_TOKEN_PARAM = "vp_token";
    private static final String RESPONSE_MODE_PARAM = "response_mode";
    private static final String DIRECT_POST_RESPONSE_MODE = "direct_post";
    private static final String STATE_PARAM = "state";
    private static final String NONCE_PARAM = "nonce";

    // OpenID4VP Authorization Request parameters.
    private static final String RESPONSE_TYPE = "vp_token";
    private static final String RESPONSE_MODE = "direct_post";

    // Context property keys.
    private static final String WALLET_STATE = "WALLET_STATE";
    private static final String WALLET_NONCE = "WALLET_NONCE";

    // Configuration property keys.
    private static final String CLIENT_ID_PROPERTY = "ClientId";
    private static final String DCQL_QUERY_PROPERTY = "DcqlQuery";
    private static final String WALLET_LOGIN_PAGE = "WalletLoginPage";

    // Default configuration values.
    private static final String DEFAULT_WALLET_LOGIN_PAGE = "walletauthenticationendpoint/wallet-login.jsp";
    private static final String DEFAULT_DCQL_QUERY = "{\"credentials\": [{\"format\": \"jwt_vc_json\", " +
            "\"claims\": [{\"path\": [\"$.vc.credentialSubject.email\"]}, " +
            "{\"path\": [\"$.vc.credentialSubject.name\"]}]}]}";

    // Secure random generator for nonce and state generation.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Get the name of the authenticator.
     *
     * @return Authenticator name.
     */
    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    /**
     * Get the friendly name of the authenticator.
     *
     * @return Friendly name to display in UI.
     */
    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Check whether the request can be handled by this authenticator.
     * Returns true if the request contains vp_token parameter or response_mode=direct_post.
     *
     * @param request HttpServletRequest.
     * @return True if the request can be handled, false otherwise.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String vpToken = request.getParameter(VP_TOKEN_PARAM);
        String responseMode = request.getParameter(RESPONSE_MODE_PARAM);

        boolean canHandle = StringUtils.isNotBlank(vpToken) ||
                DIRECT_POST_RESPONSE_MODE.equals(responseMode);

        if (LOG.isDebugEnabled()) {
            LOG.debug("WalletAuthenticator canHandle: " + canHandle + " [vpToken present: " +
                    (vpToken != null) + ", responseMode: " + responseMode + "]");
        }

        return canHandle;
    }

    /**
     * Get the context identifier sent with the request.
     *
     * @param request HttpServletRequest.
     * @return Context identifier (sessionDataKey).
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    /**
     * Initiate the OpenID4VP authentication request.
     * Generates nonce and state, constructs the authorization request, and redirects to the wallet login page.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurs during authentication initiation.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Generate secure random nonce and state.
            String nonce = generateSecureRandomString();
            String state = generateSecureRandomString();

            // Store nonce and state in the authentication context.
            context.setProperty(WALLET_NONCE, nonce);
            context.setProperty(WALLET_STATE, state);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated nonce and state for wallet authentication. State: " + state);
            }

            // Get configuration properties.
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = getClientId(authenticatorProperties);
            String dcqlQuery = getDcqlQuery(authenticatorProperties);
            String walletLoginPage = getWalletLoginPage(authenticatorProperties);

            // Construct OpenID4VP Authorization Request URI.
            String authorizationRequestUri = buildAuthorizationRequestUri(clientId, nonce, state, dcqlQuery, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Constructed OpenID4VP Authorization Request URI for wallet authentication.");
            }

            // Construct the redirect URL to wallet login page with the authorization request URI.
            String redirectUrl = buildWalletLoginPageUrl(walletLoginPage, authorizationRequestUri, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Redirecting to wallet login page: " + redirectUrl);
            }

            // Redirect to the wallet login page.
            response.sendRedirect(redirectUrl);

        } catch (IOException e) {
            LOG.error("Error occurred while redirecting to wallet login page.", e);
            throw new AuthenticationFailedException("Error occurred while initiating wallet authentication.", e);
        }
    }

    /**
     * Process the authentication response from the wallet.
     * Validates the state, extracts and verifies the VP token, and maps claims to authenticated user.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException If authentication fails.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        // Extract vp_token and state from the request.
        String vpToken = request.getParameter(VP_TOKEN_PARAM);
        String receivedState = request.getParameter(STATE_PARAM);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Processing wallet authentication response. State: " + receivedState);
        }

        // Validate that vp_token is present.
        if (StringUtils.isBlank(vpToken)) {
            LOG.error("VP token is missing in the wallet authentication response.");
            throw new AuthenticationFailedException("VP token is required for wallet authentication.");
        }

        // Retrieve the stored state from context and validate.
        String storedState = (String) context.getProperty(WALLET_STATE);
        if (StringUtils.isBlank(storedState)) {
            LOG.error("Stored state is missing in the authentication context.");
            throw new AuthenticationFailedException("Authentication context is invalid.");
        }

        if (!storedState.equals(receivedState)) {
            LOG.error("State parameter validation failed. Expected: " + storedState + ", Received: " + receivedState);
            throw new AuthenticationFailedException("State parameter validation failed. Possible CSRF attack.");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("State parameter validated successfully.");
        }

        // TODO: Verify VP Token signature using the wallet's public key or DID document.
        // This should include:
        // 1. Parse the VP token (JWT format).
        // 2. Validate the signature using the issuer's public key.
        // 3. Verify the nonce matches the one stored in context.
        // 4. Check token expiration and not-before times.
        // 5. Validate the credential status if applicable.

        // Extract claims from the VP token.
        Map<String, String> claims = extractClaimsFromVpToken(vpToken, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracted claims from VP token: " + claims.keySet());
        }

        // Create authenticated user from claims.
        AuthenticatedUser authenticatedUser = buildAuthenticatedUser(claims, context);

        // Set the authenticated user in the context.
        context.setSubject(authenticatedUser);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Wallet authentication completed successfully for user: " +
                    authenticatedUser.getAuthenticatedSubjectIdentifier());
        }
    }

    /**
     * Generate a secure random string for nonce or state.
     *
     * @return Secure random string (Base64 URL-safe encoded).
     */
    private String generateSecureRandomString() {

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Get the client ID from authenticator properties or use default.
     *
     * @param authenticatorProperties Authenticator configuration properties.
     * @return Client ID.
     */
    private String getClientId(Map<String, String> authenticatorProperties) {

        String clientId = authenticatorProperties.get(CLIENT_ID_PROPERTY);

        if (StringUtils.isBlank(clientId)) {
            // Default to WSO2 IS server URL.
            clientId = IdentityUtil.getServerURL("", true, true);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default client ID (WSO2 IS URL): " + clientId);
            }
        }

        return clientId;
    }

    /**
     * Get the DCQL query from authenticator properties or use default.
     *
     * @param authenticatorProperties Authenticator configuration properties.
     * @return DCQL query string.
     */
    private String getDcqlQuery(Map<String, String> authenticatorProperties) {

        String dcqlQuery = authenticatorProperties.get(DCQL_QUERY_PROPERTY);

        if (StringUtils.isBlank(dcqlQuery)) {
            dcqlQuery = DEFAULT_DCQL_QUERY;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default DCQL query for email and name claims.");
            }
        }

        return dcqlQuery;
    }

    /**
     * Get the wallet login page path from authenticator properties or use default.
     *
     * @param authenticatorProperties Authenticator configuration properties.
     * @return Wallet login page path.
     */
    private String getWalletLoginPage(Map<String, String> authenticatorProperties) {

        String walletLoginPage = authenticatorProperties.get(WALLET_LOGIN_PAGE);

        if (StringUtils.isBlank(walletLoginPage)) {
            walletLoginPage = DEFAULT_WALLET_LOGIN_PAGE;
        }

        return walletLoginPage;
    }

    /**
     * Build the OpenID4VP Authorization Request URI.
     *
     * @param clientId  Client identifier (WSO2 IS URL).
     * @param nonce     Nonce value.
     * @param state     State value.
     * @param dcqlQuery DCQL query for requested credentials.
     * @param context   AuthenticationContext.
     * @return Authorization Request URI.
     * @throws AuthenticationFailedException If URI encoding fails.
     */
    private String buildAuthorizationRequestUri(String clientId, String nonce, String state, String dcqlQuery,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            StringBuilder uriBuilder = new StringBuilder();
            uriBuilder.append("openid4vp://authorize?");
            uriBuilder.append("response_type=").append(URLEncoder.encode(RESPONSE_TYPE,
                    StandardCharsets.UTF_8.name()));
            uriBuilder.append("&response_mode=").append(URLEncoder.encode(RESPONSE_MODE,
                    StandardCharsets.UTF_8.name()));
            uriBuilder.append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()));
            uriBuilder.append("&nonce=").append(URLEncoder.encode(nonce, StandardCharsets.UTF_8.name()));
            uriBuilder.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8.name()));
            uriBuilder.append("&dcql_query=").append(URLEncoder.encode(dcqlQuery, StandardCharsets.UTF_8.name()));

            // Add response URI (callback endpoint for direct_post).
            String responseUri = buildResponseUri(context);
            uriBuilder.append("&response_uri=").append(URLEncoder.encode(responseUri, StandardCharsets.UTF_8.name()));

            return uriBuilder.toString();

        } catch (UnsupportedEncodingException e) {
            LOG.error("Error occurred while encoding authorization request URI parameters.", e);
            throw new AuthenticationFailedException("Failed to build authorization request URI.", e);
        }
    }

    /**
     * Build the response URI (callback endpoint) for direct_post response mode.
     *
     * @param context AuthenticationContext.
     * @return Response URI.
     */
    private String buildResponseUri(AuthenticationContext context) {

        String commonAuthUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        String sessionDataKey = context.getContextIdentifier();

        StringBuilder responseUri = new StringBuilder(commonAuthUrl);
        responseUri.append("?sessionDataKey=").append(sessionDataKey);

        return responseUri.toString();
    }

    /**
     * Build the wallet login page URL with authorization request URI as parameter.
     *
     * @param walletLoginPage        Path to wallet login JSP page.
     * @param authorizationRequestUri OpenID4VP authorization request URI.
     * @param context                 AuthenticationContext.
     * @return Full URL to wallet login page.
     * @throws AuthenticationFailedException If URL encoding fails.
     */
    private String buildWalletLoginPageUrl(String walletLoginPage, String authorizationRequestUri,
                                           AuthenticationContext context) throws AuthenticationFailedException {

        try {
            String loginPageUrl = IdentityUtil.getServerURL("", true, false) + "/" + walletLoginPage;
            String sessionDataKey = context.getContextIdentifier();
            String authenticators = getName();

            StringBuilder redirectUrl = new StringBuilder(loginPageUrl);
            redirectUrl.append("?sessionDataKey=").append(URLEncoder.encode(sessionDataKey,
                    StandardCharsets.UTF_8.name()));
            redirectUrl.append("&authenticators=").append(URLEncoder.encode(authenticators,
                    StandardCharsets.UTF_8.name()));
            redirectUrl.append("&requestUri=").append(URLEncoder.encode(authorizationRequestUri,
                    StandardCharsets.UTF_8.name()));

            return redirectUrl.toString();

        } catch (UnsupportedEncodingException e) {
            LOG.error("Error occurred while encoding wallet login page URL parameters.", e);
            throw new AuthenticationFailedException("Failed to build wallet login page URL.", e);
        }
    }

    /**
     * Extract claims from the VP token.
     * TODO: Implement full JWT parsing and validation logic.
     *
     * @param vpToken VP token (JWT format).
     * @param context AuthenticationContext.
     * @return Map of claims extracted from the VP token.
     * @throws AuthenticationFailedException If claim extraction fails.
     */
    private Map<String, String> extractClaimsFromVpToken(String vpToken, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> claims = new HashMap<>();

        try {
            // TODO: Implement proper JWT parsing and validation.
            // This is a placeholder implementation.
            // In production, you should:
            // 1. Parse the JWT token.
            // 2. Validate the signature.
            // 3. Verify the nonce.
            // 4. Extract claims from the verifiable credential.

            // Placeholder: For demonstration, extract from a mock decoded payload.
            // In real implementation, use a JWT library like Nimbus JOSE+JWT.

            // Example structure of VP token claims:
            // {
            //   "vp": {
            //     "verifiableCredential": [{
            //       "credentialSubject": {
            //         "email": "user@example.com",
            //         "name": "John Doe"
            //       }
            //     }]
            //   }
            // }

            // For now, we'll return placeholder claims.
            // Replace this with actual JWT parsing logic.
            if (LOG.isDebugEnabled()) {
                LOG.debug("TODO: Implement VP token parsing and validation. Using placeholder claims.");
            }

            // Placeholder claims - replace with actual parsing.
            claims.put("http://wso2.org/claims/emailaddress", "user@example.com");
            claims.put("http://wso2.org/claims/fullname", "Wallet User");

            // Validate nonce from the token.
            String storedNonce = (String) context.getProperty(WALLET_NONCE);
            // TODO: Extract nonce from VP token and validate against storedNonce.

            return claims;

        } catch (Exception e) {
            LOG.error("Error occurred while extracting claims from VP token.", e);
            throw new AuthenticationFailedException("Failed to extract claims from VP token.", e);
        }
    }

    /**
     * Build the authenticated user object from extracted claims.
     *
     * @param claims  Map of claims extracted from VP token.
     * @param context AuthenticationContext.
     * @return AuthenticatedUser object.
     * @throws AuthenticationFailedException If user building fails.
     */
    private AuthenticatedUser buildAuthenticatedUser(Map<String, String> claims, AuthenticationContext context)
            throws AuthenticationFailedException {

        // Extract email as the username (or use another identifier).
        String email = claims.get("http://wso2.org/claims/emailaddress");

        if (StringUtils.isBlank(email)) {
            LOG.error("Email claim is missing in the VP token. Cannot identify the user.");
            throw new AuthenticationFailedException("Email claim is required for wallet authentication.");
        }

        // Create authenticated user.
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                email);

        // Set tenant domain.
        authenticatedUser.setTenantDomain(context.getTenantDomain());

        // Set user attributes (claims).
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            ClaimMapping claimMapping = ClaimMapping.build(entry.getKey(), entry.getKey(), null, false);
            userAttributes.put(claimMapping, entry.getValue());
        }
        authenticatedUser.setUserAttributes(userAttributes);

        // Set authenticator name.
        authenticatedUser.setAuthenticatedSubjectIdentifier(email);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Built authenticated user from wallet credentials. Email: " + email);
        }

        return authenticatedUser;
    }
}

