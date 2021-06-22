package org.keycloak.protocol.oidc.par.endpoints;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import javax.ws.rs.Path;

public class ParEndpointFactory implements RealmResourceProviderFactory {

    @Override
    @Path("/par")
    public RealmResourceProvider create(KeycloakSession session) {
        ParEndpoint provider = new ParEndpoint(session);
        ResteasyProviderFactory.getInstance().injectProperties(provider);
        return provider;
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
        return "par";
    }
}
