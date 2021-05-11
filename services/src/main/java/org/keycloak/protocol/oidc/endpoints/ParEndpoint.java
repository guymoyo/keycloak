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

package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Base64Url;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.protocol.par.ParResponse;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.keycloak.protocol.oidc.OIDCLoginProtocol.REQUEST_URI_PARAM;

/**
 * Pushed Authorization Request endpoint
 */
public class ParEndpoint implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(ParEndpoint.class);
    private static final String REQUEST_URI_TEMPLATE = "urn:ietf:params:oauth:request_uri:%s";

    private KeycloakSession session;

    @Context
    private HttpRequest request;

    @Context
    private HttpResponse httpResponse;

    @Context
    private HttpHeaders headers;

    @Context
    private ClientConnection clientConnection;

    private EventBuilder event;
    private Cors cors;
    private RealmModel realm;

    public ParEndpoint(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED})
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePar() {

        LOG.info("Received PAR object");

        if (request.getFormParameters().containsKey(REQUEST_URI_PARAM)) {
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed");
        }

        KeycloakContext context = session.getContext();
        realm = context.getRealm();
        event = new EventBuilder(realm, session, context.getConnection()).event(EventType.PUSHED_AUTHORIZATION_REQUEST);

        checkSsl();
        checkRealm();
        authorizeClient();


        ClientModel clientModel = session.getContext().getClient();

        if (Boolean.parseBoolean(clientModel.getAttribute(ParConfig.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS))) {
            Map<String, String> params = new HashMap<>();
            String requestUri = String.format(REQUEST_URI_TEMPLATE, Base64Url.encode(KeycloakModelUtils.generateSecret()));

            int expiresIn = clientModel.getAttribute(ParConfig.REQUEST_URI_LIFESPAN) == null
                                    ? 60
                                    : Integer.parseInt(clientModel.getAttribute(ParConfig.REQUEST_URI_LIFESPAN));

            request.getFormParameters().forEach((k, v) -> params.put(k, String.valueOf(v)));

            PushedAuthzRequestStoreProvider parStore = session.getProvider(PushedAuthzRequestStoreProvider.class,
                                                                           "par");
            parStore.put("grantId", expiresIn, params);

            ParResponse parResponse = new ParResponse(requestUri, String.valueOf(expiresIn));
            return Response.status(Response.Status.CREATED)
                           .entity(parResponse)
                           .type(MediaType.APPLICATION_JSON_TYPE)
                           .build();
        }

        return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_request", "Pushed Authorization Request is not allowed");
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), "access_denied", "Realm not enabled", Response.Status.FORBIDDEN);
        }
    }

    private void authorizeClient() {
        try {
            ClientModel client = AuthorizeClientUtil.authorizeClient(session, event, null).getClient();

            this.event.client(client);

            if (client == null || client.isPublicClient()) {
                throw throwErrorResponseException(Errors.INVALID_REQUEST, "Client not allowed.", Response.Status.FORBIDDEN);
            }

        } catch (ErrorResponseException ere) {
            throw ere;
        } catch (Exception e) {
            throw throwErrorResponseException(Errors.INVALID_REQUEST, "Authentication failed.", Response.Status.UNAUTHORIZED);
        }
    }

    private ErrorResponseException throwErrorResponseException(String error, String detail, Response.Status status) {
        this.event.detail("detail", detail).error(error);
        return new ErrorResponseException(error, detail, status);
    }

}
