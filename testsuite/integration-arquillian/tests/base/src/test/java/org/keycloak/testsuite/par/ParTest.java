/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.par;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;
import static org.keycloak.testsuite.admin.ApiUtil.findUserByUsername;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.ws.rs.core.UriBuilder;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.events.Errors;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.client.AbstractClientPoliciesTest;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.OAuthClient.ParResponse;

@EnableFeature(value = Profile.Feature.PAR, skipRestart = true)
public class ParTest extends AbstractClientPoliciesTest {

    // defined in testrealm.json
    private static final String TEST_USER_NAME = "test-user@localhost";
    private static final String TEST_USER_PASSWORD = "password";
    private static final String TEST_USER2_NAME = "john-doh@localhost";
    private static final String TEST_USER2_PASSWORD = "password";

    private static final String CLIENT_NAME = "Zahlungs-App";
    private static final String CLIENT_REDIRECT_URI = "https://localhost:8543/auth/realms/test/app/auth/cb";
    private static final String IMAGINARY_REQUEST_URI = "urn:ietf:params:oauth:request_uri:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final int DEFAULT_REQUEST_URI_LIFESPAN = 60;
    
    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        List<UserRepresentation> users = realm.getUsers();

        LinkedList<CredentialRepresentation> credentials = new LinkedList<>();
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue("password");
        credentials.add(password);

        UserRepresentation user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername("manage-clients");
        user.setCredentials(credentials);
        user.setClientRoles(Collections.singletonMap(Constants.REALM_MANAGEMENT_CLIENT_ID, Collections.singletonList(AdminRoles.MANAGE_CLIENTS)));

        users.add(user);

        user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername("create-clients");
        user.setCredentials(credentials);
        user.setClientRoles(Collections.singletonMap(Constants.REALM_MANAGEMENT_CLIENT_ID, Collections.singletonList(AdminRoles.CREATE_CLIENT)));
        user.setGroups(Arrays.asList("topGroup")); // defined in testrealm.json

        users.add(user);

        realm.setUsers(users);

        testRealms.add(realm);
    }

    // N-01 : success with one client conducting one authz request
    @Test 
    public void testSuccessfulSinglePar() throws Exception {
        try {
            // setup PAR realm settings
            int requestUriLifespan = 45;
            setParRealmSettings(requestUriLifespan);

            // create client dynamically
            String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
                    clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
                    clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
            });
            OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
            String clientSecret = oidcCRep.getClientSecret();
            assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
            assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
            assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

            // Pushed Authorization Request
            oauth.clientId(clientId);
            oauth.redirectUri(CLIENT_REDIRECT_URI);
            ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
            assertEquals(201, pResp.getStatusCode());
            String requestUri = pResp.getRequestUri();
            assertEquals(requestUriLifespan, pResp.getExpiresIn());
 
            // Authorization Request with request_uri of PAR
            // remove parameters as query strings of uri
            oauth.redirectUri(null);
            oauth.scope(null);
            oauth.responseType(null);
            oauth.requestUri(requestUri);
            String state = oauth.stateParamRandom().getState();
            oauth.stateParamHardcoded(state);
            OAuthClient.AuthorizationEndpointResponse loginResponse = oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
            assertEquals(state, loginResponse.getState());
            String code = loginResponse.getCode();
            String sessionId =loginResponse.getSessionState();

            // Token Request
            oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
            OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);
            assertEquals(200, res.getStatusCode());

            AccessToken token = oauth.verifyToken(res.getAccessToken());
            String userId = findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER_NAME).getId();
            assertEquals(userId, token.getSubject());
            assertEquals(sessionId, token.getSessionState());
            Assert.assertNotEquals(TEST_USER_NAME, token.getSubject());
            assertEquals(clientId, token.getIssuedFor());

            // Token Refresh
            String refreshTokenString = res.getRefreshToken();
            RefreshToken refreshToken = oauth.parseRefreshToken(refreshTokenString);
            assertEquals(sessionId, refreshToken.getSessionState());
            assertEquals(clientId, refreshToken.getIssuedFor());

            OAuthClient.AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(refreshTokenString, clientSecret);
            assertEquals(200, refreshResponse.getStatusCode());

            AccessToken refreshedToken = oauth.verifyToken(refreshResponse.getAccessToken());
            RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshResponse.getRefreshToken());
            assertEquals(sessionId, refreshedToken.getSessionState());
            assertEquals(sessionId, refreshedRefreshToken.getSessionState());
            assertEquals(findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER_NAME).getId(), refreshedToken.getSubject());

            // Logout
            oauth.doLogout(refreshResponse.getRefreshToken(), clientSecret);
            refreshResponse = oauth.doRefreshTokenRequest(refreshResponse.getRefreshToken(), clientSecret);
            assertEquals(400, refreshResponse.getStatusCode());

        } finally {
            restoreParRealmSettings();
        }
    }

    // N-02 : success with the same client conducting multiple authz requests + PAR simultaneously
    @Test 
    public void testSuccessfulMultipleParBySameClient() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request #1
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUriOne = pResp.getRequestUri();

        // Pushed Authorization Request #2
        oauth.clientId(clientId);
        oauth.scope("microprofile-jwt" + " " + "profile");
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUriTwo = pResp.getRequestUri();
 
        // Authorization Request with request_uri of PAR #2
        // remove parameters as query strings of uri
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUriTwo);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        OAuthClient.AuthorizationEndpointResponse loginResponse = oauth.doLogin(TEST_USER2_NAME, TEST_USER2_PASSWORD);
        assertEquals(state, loginResponse.getState());
        String code = loginResponse.getCode();
        String sessionId =loginResponse.getSessionState();

        // Token Request #2
        oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);
        assertEquals(200, res.getStatusCode());

        AccessToken token = oauth.verifyToken(res.getAccessToken());
        String userId = findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER2_NAME).getId();
        assertEquals(userId, token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        Assert.assertNotEquals(TEST_USER2_NAME, token.getSubject());
        assertEquals(clientId, token.getIssuedFor());
        assertTrue(token.getScope().contains("openid"));
        assertTrue(token.getScope().contains("microprofile-jwt"));
        assertTrue(token.getScope().contains("profile"));

        // Logout
        oauth.doLogout(res.getRefreshToken(), clientSecret); // same oauth instance is used so that this logout is needed to send authz request consecutively.

        // Authorization Request with request_uri of PAR #1
        // remove parameters as query strings of uri
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUriOne);
        state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        loginResponse = oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
        assertEquals(state, loginResponse.getState());
        code = loginResponse.getCode();
        sessionId =loginResponse.getSessionState();

        // Token Request #1
        oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        res = oauth.doAccessTokenRequest(code, clientSecret);
        assertEquals(200, res.getStatusCode());

        token = oauth.verifyToken(res.getAccessToken());
        userId = findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER_NAME).getId();
        assertEquals(userId, token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        Assert.assertNotEquals(TEST_USER_NAME, token.getSubject());
        assertEquals(clientId, token.getIssuedFor());
        assertFalse(token.getScope().contains("microprofile-jwt"));
        assertTrue(token.getScope().contains("openid"));
    }

    // N-03 : success with several clients conducting multiple authz requests + PAR simultaneously
    @Test 
    public void testSuccessfulMultipleParByMultipleClients() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        authManageClients(); // call it when several clients are created consecutively.

        String client2Id = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcC2Rep = getClientDynamically(client2Id);
        String client2Secret = oidcC2Rep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcC2Rep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcC2Rep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcC2Rep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request #1
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUriOne = pResp.getRequestUri();

        // Pushed Authorization Request #2
        oauth.clientId(client2Id);
        oauth.scope("microprofile-jwt" + " " + "profile");
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        pResp = oauth.doPushedAuthorizationRequest(client2Id, client2Secret);
        assertEquals(201, pResp.getStatusCode());
        String requestUriTwo = pResp.getRequestUri();
 
        // Authorization Request with request_uri of PAR #2
        // remove parameters as query strings of uri
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUriTwo);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        OAuthClient.AuthorizationEndpointResponse loginResponse = oauth.doLogin(TEST_USER2_NAME, TEST_USER2_PASSWORD);
        assertEquals(state, loginResponse.getState());
        String code = loginResponse.getCode();
        String sessionId =loginResponse.getSessionState();

        // Token Request #2
        oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, client2Secret);
        assertEquals(200, res.getStatusCode());

        AccessToken token = oauth.verifyToken(res.getAccessToken());
        String userId = findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER2_NAME).getId();
        assertEquals(userId, token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        Assert.assertNotEquals(TEST_USER2_NAME, token.getSubject());
        assertEquals(client2Id, token.getIssuedFor());
        assertTrue(token.getScope().contains("openid"));
        assertTrue(token.getScope().contains("microprofile-jwt"));
        assertTrue(token.getScope().contains("profile"));

        // Logout
        oauth.doLogout(res.getRefreshToken(), client2Secret); // same oauth instance is used so that this logout is needed to send authz request consecutively.

        // Authorization Request with request_uri of PAR #1
        // remove parameters as query strings of uri
        oauth.clientId(clientId);
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUriOne);
        state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        loginResponse = oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
        assertEquals(state, loginResponse.getState());
        code = loginResponse.getCode();
        sessionId =loginResponse.getSessionState();

        // Token Request #1
        oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        res = oauth.doAccessTokenRequest(code, clientSecret);
        assertEquals(200, res.getStatusCode());

        token = oauth.verifyToken(res.getAccessToken());
        userId = findUserByUsername(adminClient.realm(REALM_NAME), TEST_USER_NAME).getId();
        assertEquals(userId, token.getSubject());
        assertEquals(sessionId, token.getSessionState());
        Assert.assertNotEquals(TEST_USER_NAME, token.getSubject());
        assertEquals(clientId, token.getIssuedFor());
        assertFalse(token.getScope().contains("microprofile-jwt"));
        assertTrue(token.getScope().contains("openid"));
    }

    // A-01 : not issued PAR used
    @Test
    public void testFailureNotIssuedParUsed() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request
        // but not use issued request_uri
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        //String requestUri = pResp.getRequestUri();
        //int expiresIn = pResp.getExpiresIn();

        // Authorization Request with request_uri of PAR
        // remove parameters as query strings of uri
        // use not issued request_uri
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(IMAGINARY_REQUEST_URI);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        UriBuilder b = UriBuilder.fromUri(oauth.getLoginFormUrl());
        driver.navigate().to(b.build().toURL());
        OAuthClient.AuthorizationEndpointResponse errorResponse = new OAuthClient.AuthorizationEndpointResponse(oauth);
        Assert.assertFalse(errorResponse.isRedirected());
    }

    // A-02 : PAR used twice
    @Test 
    public void testFailureParUsedTwice() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();

        // Authorization Request with request_uri of PAR
        // remove parameters as query strings of uri
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUri);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        OAuthClient.AuthorizationEndpointResponse loginResponse = oauth.doLogin(TEST_USER_NAME, TEST_USER_PASSWORD);
        assertEquals(state, loginResponse.getState());
        String code = loginResponse.getCode();

        // Token Request
        oauth.redirectUri(CLIENT_REDIRECT_URI); // get tokens, it needed. https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        OAuthClient.AccessTokenResponse res = oauth.doAccessTokenRequest(code, clientSecret);
        assertEquals(200, res.getStatusCode());

        // Authorization Request with request_uri of PAR
        // remove parameters as query strings of uri
        // use same redirect_uri
        state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        UriBuilder b = UriBuilder.fromUri(oauth.getLoginFormUrl());
        driver.navigate().to(b.build().toURL());
        OAuthClient.AuthorizationEndpointResponse errorResponse = new OAuthClient.AuthorizationEndpointResponse(oauth);
        Assert.assertFalse(errorResponse.isRedirected());
    }

    // A-03 : PAR used by other client
    @Test 
    public void testFailureParUsedByOtherClient() throws Exception {
        // create client dynamically
        String victimClientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation victimOidcCRep = getClientDynamically(victimClientId);
        String victimClientSecret = victimOidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, victimOidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(victimOidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, victimOidcCRep.getTokenEndpointAuthMethod());

        authManageClients();

        String attackerClientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation attackerOidcCRep = getClientDynamically(attackerClientId);
        assertEquals(Boolean.TRUE, attackerOidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(attackerOidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, attackerOidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request
        oauth.clientId(victimClientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(victimClientId, victimClientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();
 
        // Authorization Request with request_uri of PAR
        // remove parameters as query strings of uri
        // used by other client
        oauth.clientId(attackerClientId);
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUri);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        UriBuilder b = UriBuilder.fromUri(oauth.getLoginFormUrl());
        driver.navigate().to(b.build().toURL());
        OAuthClient.AuthorizationEndpointResponse errorResponse = new OAuthClient.AuthorizationEndpointResponse(oauth);
        Assert.assertFalse(errorResponse.isRedirected());
    }

    // A-04 : PAR by not allowed client
    @Test 
    public void testFailureParByNotAllowedCilent() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.FALSE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.FALSE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(400, pResp.getStatusCode());
        assertEquals(Errors.INVALID_REQUEST, pResp.getError());
    }

    // A-05 : expired PAR used
    // TODO : It seems that setTimeOffset() does not work.
    //@Test 
    public void testFailureParExpired() throws Exception {
        // create client dynamically
        String clientId = createClientDynamically(generateSuffixedName(CLIENT_NAME), (OIDCClientRepresentation clientRep) -> {
            clientRep.setRequirePushedAuthorizationRequests(Boolean.TRUE);
            clientRep.setRedirectUris(new ArrayList<String>(Arrays.asList(CLIENT_REDIRECT_URI)));
        });
        OIDCClientRepresentation oidcCRep = getClientDynamically(clientId);
        String clientSecret = oidcCRep.getClientSecret();
        assertEquals(Boolean.TRUE, oidcCRep.getRequirePushedAuthorizationRequests());
        assertTrue(oidcCRep.getRedirectUris().contains(CLIENT_REDIRECT_URI));
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, oidcCRep.getTokenEndpointAuthMethod());

        // Pushed Authorization Request
        oauth.clientId(clientId);
        oauth.redirectUri(CLIENT_REDIRECT_URI);
        ParResponse pResp = oauth.doPushedAuthorizationRequest(clientId, clientSecret);
        assertEquals(201, pResp.getStatusCode());
        String requestUri = pResp.getRequestUri();
        int expiresIn = pResp.getExpiresIn();
 
        // Authorization Request with request_uri of PAR
        // remove parameters as query strings of uri
        // PAR expired
        setTimeOffset(expiresIn + 5);
        oauth.redirectUri(null);
        oauth.scope(null);
        oauth.responseType(null);
        oauth.requestUri(requestUri);
        String state = oauth.stateParamRandom().getState();
        oauth.stateParamHardcoded(state);
        UriBuilder b = UriBuilder.fromUri(oauth.getLoginFormUrl());
        driver.navigate().to(b.build().toURL());
        OAuthClient.AuthorizationEndpointResponse errorResponse = new OAuthClient.AuthorizationEndpointResponse(oauth);
        Assert.assertFalse(errorResponse.isRedirected());
    }

    private void setParRealmSettings(int requestUriLifespan) {
        RealmRepresentation rep = adminClient.realm(REALM_NAME).toRepresentation();
        rep.setRequestUriLifespan(requestUriLifespan);
        adminClient.realm(REALM_NAME).update(rep);
    }

    private void restoreParRealmSettings() {
        setParRealmSettings(DEFAULT_REQUEST_URI_LIFESPAN);
    }
}
