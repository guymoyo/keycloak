/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc.endpoints.request;

import org.keycloak.common.util.StreamUtil;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PushedAuthzRequestStoreProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.par.ParConfig;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthorizationEndpointRequestParserProcessor {

    private static final int MILLIS_IN_SECOND = 1000;
    private static final int DEFAULT_REQUEST_URI_LIFESPAN_SECONDS = 60;

    public static AuthorizationEndpointRequest parseRequest(EventBuilder event, KeycloakSession session, ClientModel client, MultivaluedMap<String, String> requestParams) {
        try {
            AuthorizationEndpointRequest request = new AuthorizationEndpointRequest();

            AuthzEndpointQueryStringParser parser = new AuthzEndpointQueryStringParser(requestParams);
            parser.parseRequest(request);

            if (parser.getInvalidRequestMessage() != null) {
                request.invalidRequestMessage = parser.getInvalidRequestMessage();
                return request;
            }

            String requestParam = requestParams.getFirst(OIDCLoginProtocol.REQUEST_PARAM);
            String requestUriParam = requestParams.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM);

            if (requestParam != null && requestUriParam != null) {
                throw new RuntimeException("Illegal to use both 'request' and 'request_uri' parameters together");
            }

            String requestObjectRequired = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestObjectRequired();

            if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_OR_REQUEST_URI.equals(requestObjectRequired)
                        && requestParam == null && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request' or 'request_uri' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST.equals(requestObjectRequired)
                               && requestParam == null) {
                throw new RuntimeException("Client is required to use 'request' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_URI.equals(requestObjectRequired)
                               && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request_uri' parameter.");
            }

            if (requestParam != null) {
                new AuthzEndpointRequestObjectParser(session, requestParam, client).parseRequest(request);
            } else if (requestUriParam != null) {
                // Validate "requestUriParam" with allowed requestUris
                List<String> requestUris = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestUris();
                String requestUri = RedirectUtils.verifyRedirectUri(session, client.getRootUrl(), requestUriParam, new HashSet<>(requestUris), false);
                if (requestUri == null) {
                    throw new RuntimeException("Specified 'request_uri' not allowed for this client.");
                }

                // Define, if the request is `PAR` or usual `Request Object`.
                RequestUriType requestUriType = getRequestUriType(requestUri);

                if (requestUriType == RequestUriType.PAR ) {
                    if (Boolean.parseBoolean(client.getAttribute(ParConfig.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS))) {
                        enrichWithParParameters(session, requestUri, request);
                        return request;
                    } else {
                        throw new RuntimeException("Pushed Authorization Request is not allowed.");
                    }
                }

                try (InputStream is = session.getProvider(HttpClientProvider.class).get(requestUri)) {
                    String retrievedRequest = StreamUtil.readString(is);
                    new AuthzEndpointRequestObjectParser(session, retrievedRequest, client).parseRequest(request);
                }
            }

            return request;

        } catch (Exception e) {
            ServicesLogger.LOGGER.invalidRequest(e);
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static String getClientId(EventBuilder event, KeycloakSession session, MultivaluedMap<String, String> requestParams) {
        List<String> clientParam = requestParams.get(OIDCLoginProtocol.CLIENT_ID_PARAM);
        if (clientParam != null && clientParam.size() == 1) {
            return clientParam.get(0);
        } else {
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    public static RequestUriType getRequestUriType(String requestUri) {
        if (requestUri == null) {
            throw new RuntimeException("'request_uri' parameter is null");
        }

        return requestUri.toLowerCase().startsWith("urn:ietf")
                       ? RequestUriType.PAR
                       : RequestUriType.REQUEST_OBJECT;
    }

    private static void enrichWithParParameters(KeycloakSession session, String requestUri, AuthorizationEndpointRequest request) {
        PushedAuthzRequestStoreProvider parStore = session.getProvider(PushedAuthzRequestStoreProvider.class, "par");

        // TODO: parse request URI and obtain the key to load map of parameters.
        String key = "111";

        Map<String, String> retrievedRequest = parStore.remove(key);
        RealmModel realm = session.getContext().getRealm();
        int expiresIn = realm.getAttribute("requestUriLifespan", DEFAULT_REQUEST_URI_LIFESPAN_SECONDS);
        long created = Long.parseLong(retrievedRequest.get("created"));

        if (System.currentTimeMillis() - created < (expiresIn * MILLIS_IN_SECOND)) {
            // happy path - process PAR.
            for (Map.Entry<String, String> entry : retrievedRequest.entrySet()) {
                request.additionalReqParams.put(entry.getKey(), entry.getValue());
            }
        }
    }

}
