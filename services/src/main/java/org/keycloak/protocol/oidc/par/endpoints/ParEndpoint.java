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

package org.keycloak.protocol.oidc.par.endpoints;

import com.google.common.primitives.Bytes;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64Url;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.PushedAuthzRequestStoreProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.par.ParValidationService;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.protocol.oidc.par.ParResponse;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;
import org.keycloak.utils.ProfileHelper;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;


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

        ProfileHelper.requireFeature(Profile.Feature.PAR);

        LOG.debug("Received PAR object");

        KeycloakContext context = session.getContext();
        realm = context.getRealm();
        event = new EventBuilder(realm, session, context.getConnection()).event(EventType.PUSHED_AUTHORIZATION_REQUEST);

        checkSsl();
        checkRealm();
        authorizeClient();

        ClientModel clientModel = session.getContext().getClient();

        ParValidationService parValidationService = new ParValidationService(session, event);

        Response validationResponse = parValidationService.validateParRequest(request, clientModel);

        if (validationResponse != null) {
            return validationResponse;
        }

        Map<String, String> params = new HashMap<>();

        byte[] clientHashAndSecret = Bytes.concat(getHash(clientModel.getClientId()), KeycloakModelUtils.generateSecret());
        String requestUri = String.format(REQUEST_URI_TEMPLATE, Base64Url.encode(clientHashAndSecret));

        int expiresIn = realm.getAttribute("requestUriLifespan", 60);

        request.getFormParameters().forEach((k, v) -> params.put(k, String.valueOf(v)));
        params.put("created", String.valueOf(System.currentTimeMillis()));

        PushedAuthzRequestStoreProvider parStore = session.getProvider(PushedAuthzRequestStoreProvider.class,
                                                                       "par");
        parStore.put(requestUri, expiresIn, params);

        ParResponse parResponse = new ParResponse(requestUri, String.valueOf(expiresIn));
        return Response.status(Response.Status.CREATED)
                       .entity(parResponse)
                       .type(MediaType.APPLICATION_JSON_TYPE)
                       .build();
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

    private byte[] getHash(String inputData) {
        byte[] hash;

        try {
            hash = MessageDigest.getInstance("SHA-256")
                    .digest(inputData.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Error calculating hash");
        }

        return hash;
    }

    private ErrorResponseException throwErrorResponseException(String error, String detail, Response.Status status) {
        this.event.detail("detail", detail).error(error);
        return new ErrorResponseException(error, detail, status);
    }

}
