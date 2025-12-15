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

/**
 * Constants for Wallet Authenticator configuration.
 * This class contains all configuration property keys and default values.
 */
public class WalletAuthenticatorConstants {

    /**
     * Private constructor to prevent instantiation.
     */
    private WalletAuthenticatorConstants() {

    }

    // Authenticator metadata.
    public static final String AUTHENTICATOR_NAME = "WalletAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet Login";

    // Configuration property keys.
    public static final String CLIENT_ID = "ClientId";
    public static final String DCQL_QUERY = "DcqlQuery";
    public static final String WALLET_LOGIN_PAGE = "WalletLoginPage";
    public static final String RESPONSE_URI = "ResponseUri";
    public static final String TRUSTED_ISSUERS = "TrustedIssuers";
    public static final String CLAIM_MAPPINGS = "ClaimMappings";

    // Default configuration values.
    public static final String DEFAULT_WALLET_LOGIN_PAGE = "walletauthenticationendpoint/wallet-login.jsp";
    public static final String DEFAULT_DCQL_QUERY = "{\"credentials\": [{\"format\": \"jwt_vc_json\", " +
            "\"claims\": [{\"path\": [\"$.vc.credentialSubject.email\"]}, " +
            "{\"path\": [\"$.vc.credentialSubject.name\"]}]}]}";

    // OpenID4VP protocol constants.
    public static final String VP_TOKEN_PARAM = "vp_token";
    public static final String PRESENTATION_SUBMISSION_PARAM = "presentation_submission";
    public static final String STATE_PARAM = "state";
    public static final String NONCE_PARAM = "nonce";
    public static final String RESPONSE_MODE_PARAM = "response_mode";
    public static final String RESPONSE_TYPE = "vp_token";
    public static final String RESPONSE_MODE = "direct_post";
    public static final String DIRECT_POST_RESPONSE_MODE = "direct_post";

    // Context property keys.
    public static final String WALLET_STATE = "WALLET_STATE";
    public static final String WALLET_NONCE = "WALLET_NONCE";
    public static final String WALLET_REQUEST_URI = "WALLET_REQUEST_URI";

    // VP Token claim paths.
    public static final String VP_CLAIM_PATH = "vp";
    public static final String VC_CLAIM_PATH = "verifiableCredential";
    public static final String CREDENTIAL_SUBJECT_PATH = "credentialSubject";

    // Default claim URIs.
    public static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    public static final String FULL_NAME_CLAIM_URI = "http://wso2.org/claims/fullname";
    public static final String GIVEN_NAME_CLAIM_URI = "http://wso2.org/claims/givenname";
    public static final String FAMILY_NAME_CLAIM_URI = "http://wso2.org/claims/lastname";

    // Error codes.
    public static final String ERROR_CODE_MISSING_VP_TOKEN = "WALLET_AUTH_001";
    public static final String ERROR_CODE_INVALID_STATE = "WALLET_AUTH_002";
    public static final String ERROR_CODE_VP_VERIFICATION_FAILED = "WALLET_AUTH_003";
    public static final String ERROR_CODE_NONCE_VALIDATION_FAILED = "WALLET_AUTH_004";
    public static final String ERROR_CODE_MISSING_REQUIRED_CLAIMS = "WALLET_AUTH_005";
    public static final String ERROR_CODE_UNTRUSTED_ISSUER = "WALLET_AUTH_006";

    // Error messages.
    public static final String ERROR_MSG_MISSING_VP_TOKEN = "VP token is required for wallet authentication.";
    public static final String ERROR_MSG_INVALID_STATE = "State parameter validation failed. Possible CSRF attack.";
    public static final String ERROR_MSG_VP_VERIFICATION_FAILED = "VP token verification failed.";
    public static final String ERROR_MSG_NONCE_VALIDATION_FAILED = "Nonce validation failed. Possible replay attack.";
    public static final String ERROR_MSG_MISSING_REQUIRED_CLAIMS = "Required claims are missing in the VP token.";
    public static final String ERROR_MSG_UNTRUSTED_ISSUER = "VP token issuer is not trusted.";

    /**
     * Nested class for configuration property descriptions.
     */
    public static class ConfigProperties {

        public static final String CLIENT_ID_DESCRIPTION = "Client identifier for OpenID4VP requests. " +
                "Defaults to WSO2 IS server URL if not configured.";

        public static final String DCQL_QUERY_DESCRIPTION = "DCQL (Decentralized Credential Query Language) query " +
                "for requesting specific credentials from the wallet. " +
                "Example: {\"credentials\": [{\"format\": \"jwt_vc_json\", " +
                "\"claims\": [{\"path\": [\"$.vc.credentialSubject.email\"]}]}]}";

        public static final String WALLET_LOGIN_PAGE_DESCRIPTION = "Path to the wallet login JSP page " +
                "that displays the QR code. Relative to the authentication endpoint.";

        public static final String RESPONSE_URI_DESCRIPTION = "Callback URI where the wallet will POST the VP token. " +
                "Defaults to the common auth endpoint.";

        public static final String TRUSTED_ISSUERS_DESCRIPTION = "Comma-separated list of trusted credential " +
                "issuer DIDs. Only credentials from these issuers will be accepted.";

        public static final String CLAIM_MAPPINGS_DESCRIPTION = "JSON configuration for mapping VP token claims to " +
                "local claims. Example: [{\"vcClaim\": \"$.vc.credentialSubject.email\", " +
                "\"localClaim\": \"http://wso2.org/claims/emailaddress\"}]";
    }

    /**
     * Nested class for HTTP parameter names.
     */
    public static class RequestParams {

        public static final String SESSION_DATA_KEY = "sessionDataKey";
        public static final String AUTHENTICATORS = "authenticators";
        public static final String REQUEST_URI = "requestUri";
    }
}

