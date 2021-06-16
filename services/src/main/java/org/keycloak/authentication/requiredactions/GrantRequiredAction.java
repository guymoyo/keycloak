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

package org.keycloak.authentication.requiredactions;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.enums.GrantIdSupportedOptions;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;


public class GrantRequiredAction implements RequiredActionProvider {
    private static final Logger logger = Logger.getLogger(GrantRequiredAction.class);
    public static final String GRANT_ID_SUPPORTED = "grantIdSupported";
    public static final String GRANT_ACCEPTED = "grantAccepted";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        String grantAccepted = context.getAuthenticationSession().getClientNote(GRANT_ACCEPTED);
        if (grantAccepted != null) {
            context.getAuthenticationSession().removeAuthNote(GRANT_ACCEPTED);
            return;
        }

        String grantIdSupportedOptionAttr = context.getRealm().getAttribute(GRANT_ID_SUPPORTED);
        GrantIdSupportedOptions grantIdSupportedOption;
        if (grantIdSupportedOptionAttr == null) {
            grantIdSupportedOption = GrantIdSupportedOptions.NONE;
        } else {
            grantIdSupportedOption = GrantIdSupportedOptions.valueOf(grantIdSupportedOptionAttr);
        }

        ClientModel client = context.getAuthenticationSession().getClient();
        boolean clientGrantIdRequired = OIDCAdvancedConfigWrapper.fromClientModel(client).getGrantIdRequired();
        //TODO
        //String authorizationDetails = context.getAuthenticationSession().getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM);
        //if (StringUtils.isNotEmpty(authorizationDetails)) ...

        if (GrantIdSupportedOptions.ALWAYS.equals(grantIdSupportedOption)
                || (GrantIdSupportedOptions.OPTIONAL.equals(grantIdSupportedOption) && clientGrantIdRequired)) {

            context.getUser().addRequiredAction(UserModel.RequiredAction.GRANT_REQUIRED);
            logger.debug("User is required to accept or reject the grant");
        }

    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {

        String authorizationDetails = context.getAuthenticationSession().getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM);
        //the authorizationDetails coming from client can be enrich with data coming from a resource
        //TODO: when merge with RAR branch, Response challenge = context.form()
        // .setAttribute("authorizationDetail", rarProcessor.enrich(authorizationDetail))
        // .createForm(rarProcessor.getTemplateName());
        Response challenge = context.form()
                .setAttribute("authorizationDetails", authorizationDetails)
                .createForm("grant-required.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent().clone().event(EventType.GRANT_CONSENT).detail(Details.CONSENT, context.getUser().getUsername());
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        UserModel user = authSession.getAuthenticatedUser();
        ClientModel client = authSession.getClient();
        RealmModel realm = context.getRealm();

        if (formData.containsKey("cancel")) {
            cleanSession(context, RequiredActionContext.KcActionStatus.CANCELLED);
            context.failure();
            event.error(Errors.CONSENT_DENIED);
            return;
        }

        String grantId = authSession.getAuthNote(OIDCLoginProtocol.GRANT_ID_PARAM);
        GrantService grantService = context.getSession().getProvider(GrantService.class);
        long currentTime = Time.currentTimeMillis();

        try {
            UserGrantModel userGrantModel;
            if (StringUtils.isEmpty(grantId)) {
                userGrantModel = new UserGrantModel();
                grantId = Base64Url.encode(KeycloakModelUtils.generateSecret());
                userGrantModel.setGrantId(grantId);
                userGrantModel.setClientId(client.getClientId());
                userGrantModel.setUserId(user.getId());
                userGrantModel.setScopes(authSession.getAuthNote(OIDCLoginProtocol.SCOPE_PARAM));
                userGrantModel.setClaims(authSession.getAuthNote(OIDCLoginProtocol.CLAIMS_PARAM));
                //User can select some additional parameter that we sent to the template previously, we need to combine
                //TODO: when merging with RAR, userGrantModel.setAuthorizationDetails(rarProcessor.finaliseAuthorizationDetails(formData, authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM)));
                userGrantModel.setAuthorizationDetails(authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM));
                userGrantModel.setCreatedDate(currentTime);
                userGrantModel.setLastUpdatedDate(currentTime);
                grantService.adduserGrant(realm, userGrantModel);

            } else {
                userGrantModel = grantService.getGrantByGrantId(realm, grantId, client.getClientId());
                if (userGrantModel == null || !StringUtils.equals(user.getId(), userGrantModel.getUserId())) {
                    cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
                    context.failure();
                    event.error(Errors.INVALID_GRANT_ID);
                    return;
                }
                userGrantModel.setScopes(authSession.getAuthNote(OIDCLoginProtocol.SCOPE_PARAM));
                userGrantModel.setClaims(authSession.getAuthNote(OIDCLoginProtocol.CLAIMS_PARAM));
                //User can select some additional parameter that we sent to the template previously, we need to combine
                //TODO: when merging with RAR, userGrantModel.setAuthorizationDetails(rarProcessor.finaliseAuthorizationDetails(formData, authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM)));
                userGrantModel.setAuthorizationDetails(authSession.getAuthNote(OIDCLoginProtocol.AUTHORIZATION_DETAILS_PARAM));
                userGrantModel.setLastUpdatedDate(currentTime);
                grantService.updateUserGrant(realm, userGrantModel);
            }
        } catch (Exception e) {
            cleanSession(context, RequiredActionContext.KcActionStatus.ERROR);
            context.failure();
            event.error(Errors.INVALID_GRANT_ID);
            return;
        }

        cleanSession(context, RequiredActionContext.KcActionStatus.SUCCESS);
        authSession.setClientNote(OIDCLoginProtocol.GRANT_ID_PARAM, grantId);
        authSession.setClientNote(GRANT_ACCEPTED, GRANT_ACCEPTED);
        context.success();
    }

    private void cleanSession(RequiredActionContext context, RequiredActionContext.KcActionStatus status) {
        context.getAuthenticationSession().removeRequiredAction(UserModel.RequiredAction.GRANT_REQUIRED.name());
        context.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
        AuthenticationManager.setKcActionStatus(UserModel.RequiredAction.GRANT_REQUIRED.name(), status, context.getAuthenticationSession());
    }

    @Override
    public void close() {

    }
}
