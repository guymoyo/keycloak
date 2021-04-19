package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.CodeToTokenStoreProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.par.ParResponse;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ParEndpoint implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(ParEndpoint.class);

    private final KeycloakSession session;

    public ParEndpoint(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @NoCache
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED})
    public Response handlePar(MultivaluedMap<String, String> formData) {

        LOG.info("Received PAR object");

        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        EventBuilder event = new EventBuilder(realm, session, context.getConnection());

        CodeToTokenStoreProvider codeStore = session.getProvider(CodeToTokenStoreProvider.class,
                                                                 "infinispan");
        Map<String, String> params = new HashMap<>();
        UUID grantId = UUID.randomUUID();

        int expiresIn = 9000;

        formData.forEach((k, v) -> params.put(k, String.valueOf(v)));

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
