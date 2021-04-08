package org.keycloak.protocol.oidc;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.endpoints.ParEndpoint;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ParEndpointFactory implements RealmResourceProviderFactory {

    private static final String PROVIDER_ID = "par";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new ParEndpoint(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
