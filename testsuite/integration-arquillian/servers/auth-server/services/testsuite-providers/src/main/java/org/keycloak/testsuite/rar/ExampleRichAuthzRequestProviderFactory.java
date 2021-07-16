package org.keycloak.testsuite.rar;

import org.keycloak.Config;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.rar.RichAuthzRequestProvider;
import org.keycloak.protocol.oidc.rar.RichAuthzRequestProviderFactory;

public class ExampleRichAuthzRequestProviderFactory implements RichAuthzRequestProviderFactory {
    @Override
    public RichAuthzRequestProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        return new ExampleRichAuthzRequestProvider(session, realm);
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
