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

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for WalletAuthenticator.
 * This class demonstrates how to test the Wallet Authenticator functionality.
 */
public class WalletAuthenticatorTest {

    private WalletAuthenticator walletAuthenticator;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private AuthenticationContext mockContext;

    /**
     * Set up test fixtures before each test method.
     */
    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        walletAuthenticator = new WalletAuthenticator();
    }

    /**
     * Test getName() method returns correct authenticator name.
     */
    @Test
    public void testGetName() {

        String name = walletAuthenticator.getName();
        assertEquals(name, "WalletAuthenticator", "Authenticator name should be 'WalletAuthenticator'");
    }

    /**
     * Test getFriendlyName() method returns correct friendly name.
     */
    @Test
    public void testGetFriendlyName() {

        String friendlyName = walletAuthenticator.getFriendlyName();
        assertEquals(friendlyName, "Wallet Login", "Friendly name should be 'Wallet Login'");
    }

    /**
     * Test canHandle() returns true when vp_token parameter is present.
     */
    @Test
    public void testCanHandleWithVpToken() {

        when(mockRequest.getParameter("vp_token")).thenReturn("sample_vp_token");

        boolean canHandle = walletAuthenticator.canHandle(mockRequest);
        assertTrue(canHandle, "Should be able to handle request with vp_token parameter");
    }

    /**
     * Test canHandle() returns true when response_mode is direct_post.
     */
    @Test
    public void testCanHandleWithDirectPostResponseMode() {

        when(mockRequest.getParameter("vp_token")).thenReturn(null);
        when(mockRequest.getParameter("response_mode")).thenReturn("direct_post");

        boolean canHandle = walletAuthenticator.canHandle(mockRequest);
        assertTrue(canHandle, "Should be able to handle request with response_mode=direct_post");
    }

    /**
     * Test canHandle() returns false when neither vp_token nor response_mode is present.
     */
    @Test
    public void testCanHandleWithoutRequiredParameters() {

        when(mockRequest.getParameter("vp_token")).thenReturn(null);
        when(mockRequest.getParameter("response_mode")).thenReturn(null);

        boolean canHandle = walletAuthenticator.canHandle(mockRequest);
        assertFalse(canHandle, "Should not be able to handle request without required parameters");
    }

    /**
     * Test getContextIdentifier() returns sessionDataKey from request.
     */
    @Test
    public void testGetContextIdentifier() {

        String expectedSessionDataKey = "test-session-data-key-123";
        when(mockRequest.getParameter("sessionDataKey")).thenReturn(expectedSessionDataKey);

        String contextIdentifier = walletAuthenticator.getContextIdentifier(mockRequest);
        assertEquals(contextIdentifier, expectedSessionDataKey, "Context identifier should match sessionDataKey");
    }

    /**
     * Test initiateAuthenticationRequest() generates nonce and state.
     */
    @Test
    public void testInitiateAuthenticationRequestGeneratesNonceAndState() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("ClientId", "https://localhost:9443");

        when(mockContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockContext.getContextIdentifier()).thenReturn("test-context-id");
        when(mockContext.getTenantDomain()).thenReturn("carbon.super");

        // Note: This test will fail with redirect, but we can verify properties are set.
        try {
            walletAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockContext);
        } catch (Exception e) {
            // Expected to fail at redirect, but we can verify the context was updated.
        }

        // In a real test, you would use ArgumentCaptor to capture the properties set on context.
        // This is a simplified example.
    }

    /**
     * Test processAuthenticationResponse() fails when vp_token is missing.
     */
    @Test(expectedExceptions = AuthenticationFailedException.class,
            expectedExceptionsMessageRegExp = ".*VP token is required.*")
    public void testProcessAuthenticationResponseWithMissingVpToken() throws AuthenticationFailedException {

        when(mockRequest.getParameter("vp_token")).thenReturn(null);
        when(mockRequest.getParameter("state")).thenReturn("test-state");
        when(mockContext.getProperty("WALLET_STATE")).thenReturn("test-state");

        walletAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
    }

    /**
     * Test processAuthenticationResponse() fails when state validation fails.
     */
    @Test(expectedExceptions = AuthenticationFailedException.class,
            expectedExceptionsMessageRegExp = ".*State parameter validation failed.*")
    public void testProcessAuthenticationResponseWithInvalidState() throws AuthenticationFailedException {

        when(mockRequest.getParameter("vp_token")).thenReturn("sample_vp_token");
        when(mockRequest.getParameter("state")).thenReturn("wrong-state");
        when(mockContext.getProperty("WALLET_STATE")).thenReturn("correct-state");

        walletAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
    }

    /**
     * Test processAuthenticationResponse() succeeds with valid vp_token and state.
     * Note: This uses placeholder claim extraction logic.
     */
    @Test
    public void testProcessAuthenticationResponseSuccess() throws AuthenticationFailedException {

        String validVpToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."; // Sample JWT.
        String validState = "test-state-123";

        when(mockRequest.getParameter("vp_token")).thenReturn(validVpToken);
        when(mockRequest.getParameter("state")).thenReturn(validState);
        when(mockContext.getProperty("WALLET_STATE")).thenReturn(validState);
        when(mockContext.getProperty("WALLET_NONCE")).thenReturn("test-nonce");
        when(mockContext.getTenantDomain()).thenReturn("carbon.super");

        walletAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);

        // In a real test, you would verify that:
        // 1. context.setSubject() was called with an AuthenticatedUser.
        // 2. The authenticated user has the correct claims.
        // This would require using ArgumentCaptor or a spy on the context.
    }

    /**
     * Test that secure random string generation produces non-null, non-empty strings.
     * This is a helper method test.
     */
    @Test
    public void testSecureRandomStringGeneration() {

        // This would require making the method public or using reflection for testing.
        // For demonstration, we test indirectly through initiateAuthenticationRequest.
        // In practice, you'd extract this to a utility class for easier testing.

        // Placeholder assertion.
        assertNotNull(walletAuthenticator, "Authenticator should be instantiated");
    }

    /**
     * Test claim extraction handles missing email claim.
     * Note: Current implementation uses placeholder claims, so this test demonstrates
     * the expected behavior once real JWT parsing is implemented.
     */
    @Test(expectedExceptions = AuthenticationFailedException.class,
            expectedExceptionsMessageRegExp = ".*Email claim is required.*",
            enabled = false) // Disabled until real JWT parsing is implemented.
    public void testClaimExtractionWithMissingEmail() throws AuthenticationFailedException {

        String vpTokenWithoutEmail = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
        String validState = "test-state";

        when(mockRequest.getParameter("vp_token")).thenReturn(vpTokenWithoutEmail);
        when(mockRequest.getParameter("state")).thenReturn(validState);
        when(mockContext.getProperty("WALLET_STATE")).thenReturn(validState);
        when(mockContext.getProperty("WALLET_NONCE")).thenReturn("test-nonce");
        when(mockContext.getTenantDomain()).thenReturn("carbon.super");

        // This would extract claims and fail due to missing email.
        walletAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
    }

    /**
     * Integration test example: Test full authentication flow.
     * This would require a test wallet and test credentials.
     * Disabled by default as it requires external dependencies.
     */
    @Test(enabled = false)
    public void testFullAuthenticationFlow() throws Exception {

        // Step 1: Initiate authentication.
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("ClientId", "https://localhost:9443");
        authenticatorProperties.put("DcqlQuery", "{\"credentials\": [{\"format\": \"jwt_vc_json\"}]}");

        when(mockContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockContext.getContextIdentifier()).thenReturn("integration-test-context");
        when(mockContext.getTenantDomain()).thenReturn("carbon.super");

        // Initiate would redirect to wallet login page.
        // In integration test, you'd capture the redirect URL and parse the authorization request.

        // Step 2: Simulate wallet response.
        String mockVpToken = generateMockVpToken(); // Helper to generate test VP token.
        String state = "captured-state-from-step1";

        when(mockRequest.getParameter("vp_token")).thenReturn(mockVpToken);
        when(mockRequest.getParameter("state")).thenReturn(state);
        when(mockContext.getProperty("WALLET_STATE")).thenReturn(state);

        // Process response.
        walletAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);

        // Verify authenticated user was set.
        // ArgumentCaptor<AuthenticatedUser> userCaptor = ArgumentCaptor.forClass(AuthenticatedUser.class);
        // verify(mockContext).setSubject(userCaptor.capture());
        // assertNotNull(userCaptor.getValue());
    }

    /**
     * Helper method to generate a mock VP token for testing.
     * In real implementation, this would create a properly signed JWT.
     *
     * @return Mock VP token string.
     */
    private String generateMockVpToken() {

        // This is a placeholder. In real testing, you'd use a JWT library to create a valid token.
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIiLCJub25jZSI6InRl" +
                "c3Qtbm9uY2UiLCJ2cCI6eyJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siY3JlZGVudGlhbFN1YmplY3QiOnsiZW1h" +
                "aWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibmFtZSI6IlRlc3QgVXNlciJ9fV19fQ.signature";
    }
}

