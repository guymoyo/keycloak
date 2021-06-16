package org.keycloak.testsuite.rar;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.rar.RichAuthzRequestProcessorProvider;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ExampleRichAuthzRequestProcessorProvider implements RichAuthzRequestProcessorProvider {

    private final KeycloakSession session;
    private final RealmModel realm;

    private PaymentInitiation paymentInitiation;
    private AccountInformation accountInformation;

    public static final List<String> AUTHORIZATION_DETAILS_TYPES_SUPPORTED = Arrays.asList("payment_initiation", "account_information");

    public ExampleRichAuthzRequestProcessorProvider(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    @Override
    public void close() {

    }

    @Override
    public void checkAuthorizationDetails(String authorizationDetailsJson, List<String> authorizationDetailsTypes) throws Exception {
        convertAuthorizationDetailsJsonToObjet(authorizationDetailsJson);
        if (paymentInitiation == null && accountInformation == null) {
            throw new Exception("authorization details not conforming to the respective type definition");
        }

        if (paymentInitiation != null) {
            if (paymentInitiation.getType() == null || !"payment_initiation".equals(paymentInitiation.getType())) {
                throw new Exception("unknown authorization data type");
            }

            if (paymentInitiation.getCreditorAccount() == null || paymentInitiation.getInstructedAmount() == null) {
                throw new Exception("required elements of authorization details are missing");
            }
        }

        if (accountInformation != null) {
            if (accountInformation.getType() == null || !"account_information".equals(accountInformation.getType())) {
                throw new Exception("unknown authorization data type");
            }

            if (accountInformation.getIban() == null) {
                throw new Exception("required elements of authorization details are missing");
            }
        }
    }

    @Override
    public List<String> getAuthorizationDetailsTypesSupported() {
        return AUTHORIZATION_DETAILS_TYPES_SUPPORTED;
    }

    @Override
    public String mergeAuthorizationDetails(String newAuthorizationDetailsJson, String oldAuthorizationDetailsJson) {
        return oldAuthorizationDetailsJson;
    }

    @Override
    public Object enrichAuthorizationDetails(String authorizationDetailsJson) {
        return authorizationDetailsJson;
    }

    @Override
    public String getTemplateName() {
        return null;
    }

    @Override
    public String finaliseAuthorizationDetails(MultivaluedMap<String, String> formData, String authorizationDetailsJson) {
        return authorizationDetailsJson;
    }

    private void convertAuthorizationDetailsJsonToObjet(String authorizationDetailsJson) {
        try {
             paymentInitiation = JsonSerialization.readValue(authorizationDetailsJson, PaymentInitiation.class);
        } catch (IOException ioe) {
        }

        try {
            accountInformation = JsonSerialization.readValue(authorizationDetailsJson, AccountInformation.class);
        } catch (IOException ioe) {
        }
    }
}
