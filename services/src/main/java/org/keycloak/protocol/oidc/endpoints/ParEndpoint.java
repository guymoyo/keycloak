package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PushedAuthzRequestStoreProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.protocol.par.ParResponse;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.keycloak.protocol.oidc.OIDCLoginProtocol.REQUEST_URI_PARAM;

/**
 * FAPI 2.0 Pushed Authorization Request endpoint
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

        Map<String, String> params = new HashMap<>();
        String requestUri = String.format(REQUEST_URI_TEMPLATE, UUID.randomUUID().toString());

        int expiresIn = OIDCAdvancedConfigWrapper.fromClientModel(session.getContext().getClient()).getRequestUriLifespan();

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
