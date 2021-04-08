package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authentication.ParResponse;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ParEndpoint implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(ParEndpoint.class);

    public static final String OBJECT_ID = "objectId";
    public static final String REDIRECT_ID = "redirectId";
    public static final String OBJECT_TYPE = "objectType";
    public static final String USERNAME = "username";
    public static final String CLIENT_ID = "clientId";
    public static final String REDIRECT_URI = "redirect_uri";

    private final KeycloakSession session;

    public ParEndpoint(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @NoCache
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED})
    public Response handlePar(@FormParam(OBJECT_ID) String objectId,
                              @FormParam(REDIRECT_ID) String redirectId,
                              @FormParam(OBJECT_TYPE) String objectType,
                              @FormParam(USERNAME) String username,
                              @FormParam(REDIRECT_URI) String redirectUri,
                              @FormParam(CLIENT_ID) final String clientId) {

        LOG.info("Received PAR for object ID: " + objectId);

        CodeToTokenStoreProvider codeStore = session.getProvider(CodeToTokenStoreProvider.class,
                                                                 "infinispan");
        Map<String, String> params = new HashMap<>();

        params.put(OBJECT_ID, objectId);
        params.put(REDIRECT_ID, redirectId);
        params.put(OBJECT_TYPE, objectType);

        UUID grantId = UUID.randomUUID();

        int expiresIn = 9000;

        codeStore.put(grantId, expiresIn, params);

        ParResponse parResponse = new ParResponse(grantId.toString(), String.valueOf(expiresIn));

        return Response.ok(parResponse, MediaType.APPLICATION_JSON_TYPE)
                       .build();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }
}
