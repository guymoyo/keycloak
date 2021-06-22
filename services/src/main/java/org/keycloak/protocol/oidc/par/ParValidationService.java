package org.keycloak.protocol.oidc.par;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequestParserProcessor;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.keycloak.protocol.oidc.OIDCLoginProtocol.REQUEST_URI_PARAM;

public class ParValidationService {

    private KeycloakSession session;
    private EventBuilder event;
    private AuthorizationEndpointRequest authorizationRequest;
    private String redirectUri;

    public ParValidationService(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.event = event;
    }

    public Response validateParRequest(HttpRequest request, ClientModel clientModel) {

        if (request.getDecodedFormParameters().containsKey(REQUEST_URI_PARAM)) {
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_REQUEST, "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed");
        }

        authorizationRequest = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, clientModel, request.getDecodedFormParameters());

        checkRedirectUri(clientModel);
        Response errorResponse = checkResponseType(clientModel);
        if (errorResponse != null) {
            return errorResponse;
        }

        if (authorizationRequest.getInvalidRequestMessage() != null) {
            event.error(Errors.INVALID_REQUEST);
            throw throwErrorResponseException(Errors.INVALID_REQUEST, authorizationRequest.getInvalidRequestMessage(), Response.Status.BAD_REQUEST);
        }

        if (!TokenUtil.isOIDCRequest(authorizationRequest.getScope())) {
            ServicesLogger.LOGGER.oidcScopeMissing();
        }

        if (!TokenManager.isValidScope(authorizationRequest.getScope(), clientModel)) {
            ServicesLogger.LOGGER.invalidParameter(OIDCLoginProtocol.SCOPE_PARAM);
            event.error(Errors.INVALID_REQUEST);
            throw throwErrorResponseException(Errors.INVALID_REQUEST, "Invalid scopes: " + authorizationRequest.getScope(), Response.Status.BAD_REQUEST);
        }

        return null;
    }

    private Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private void checkRedirectUri(ClientModel clientModel) {
        String redirectUriParam = authorizationRequest.getRedirectUriParam();
        boolean isOIDCRequest = TokenUtil.isOIDCRequest(authorizationRequest.getScope());

        event.detail(Details.REDIRECT_URI, redirectUriParam);

        redirectUri = RedirectUtils.verifyRedirectUri(session, redirectUriParam, clientModel, isOIDCRequest);
        if (redirectUri == null) {
            event.error(Errors.INVALID_REDIRECT_URI);
            throw throwErrorResponseException(Errors.INVALID_REQUEST, "Invalid parameter: redirect_uri", Response.Status.BAD_REQUEST);
        }
    }

    private Response checkResponseType(ClientModel clientModel) {
        String responseType = authorizationRequest.getResponseType();

        if (responseType == null) {
            ServicesLogger.LOGGER.missingParameter(OAuth2Constants.RESPONSE_TYPE);
            event.error(Errors.INVALID_REQUEST);
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_REQUEST, "Missing parameter: response_type");
        }

        event.detail(Details.RESPONSE_TYPE, responseType);
        OIDCResponseType parsedResponseType;

        try {
            parsedResponseType = OIDCResponseType.parse(responseType);
        } catch (IllegalArgumentException iae) {
            event.error(Errors.INVALID_REQUEST);
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_REQUEST, "Unsupported response type");
        }

        OIDCResponseMode parsedResponseMode;
        try {
            parsedResponseMode = OIDCResponseMode.parse(authorizationRequest.getResponseMode(), parsedResponseType);
        } catch (IllegalArgumentException iae) {
            ServicesLogger.LOGGER.invalidParameter(OIDCLoginProtocol.RESPONSE_MODE_PARAM);
            event.error(Errors.INVALID_REQUEST);
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_REQUEST, "Invalid parameter: response_mode");
        }

        event.detail(Details.RESPONSE_MODE, parsedResponseMode.toString().toLowerCase());

        // Disallowed by OIDC specs
        if (parsedResponseType.isImplicitOrHybridFlow() && parsedResponseMode == OIDCResponseMode.QUERY) {
            ServicesLogger.LOGGER.responseModeQueryNotAllowed();
            event.error(Errors.INVALID_REQUEST);
            return errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_REQUEST, "Response_mode 'query' not allowed for implicit or hybrid flow");
        }

        if ((parsedResponseType.hasResponseType(OIDCResponseType.CODE) || parsedResponseType.hasResponseType(OIDCResponseType.NONE)) && !clientModel.isStandardFlowEnabled()) {
            ServicesLogger.LOGGER.flowNotAllowed("Standard");
            event.error(Errors.NOT_ALLOWED);
            return errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), OAuthErrorException.UNAUTHORIZED_CLIENT, "Client is not allowed to initiate browser login with given response_type. Standard flow is disabled for the client.");
        }

        if (parsedResponseType.isImplicitOrHybridFlow() && !clientModel.isImplicitFlowEnabled()) {
            ServicesLogger.LOGGER.flowNotAllowed("Implicit");
            event.error(Errors.NOT_ALLOWED);
            return errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), OAuthErrorException.UNAUTHORIZED_CLIENT, "Client is not allowed to initiate browser login with given response_type. Implicit flow is disabled for the client.");
        }

        return null;
    }

    private ErrorResponseException throwErrorResponseException(String error, String detail, Response.Status status) {
        this.event.detail("detail", detail).error(error);
        return new ErrorResponseException(error, detail, status);
    }

}
