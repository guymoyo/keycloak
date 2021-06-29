package org.keycloak.protocol.oidc.rar.impl;

import org.keycloak.Config;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.rar.RichAuthzRequestProcessorProvider;
import org.keycloak.protocol.oidc.rar.RichAuthzRequestProcessorProviderFactory;

public class ExampleRichAuthzRequestProcessorProviderFactory implements RichAuthzRequestProcessorProviderFactory {
    @Override
    public RichAuthzRequestProcessorProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        return new ExampleRichAuthzRequestProcessorProvider(session, realm);
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
        return "ExampleRichAuthzRequestProcessor";
    }
}
