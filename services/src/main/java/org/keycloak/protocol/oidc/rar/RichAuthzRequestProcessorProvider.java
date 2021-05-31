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
package org.keycloak.protocol.oidc.rar;

import org.keycloak.provider.Provider;

import java.util.List;

public interface RichAuthzRequestProcessorProvider extends Provider {

    /**
     * This method do several check such as:
     * syntax check, if the authorizationDetails Json Object is valid
     * conforming to the respective types definition supported
     * check the required field
     *
     * @param authorizationDetailsJson
     */
   void checkAuthorizationDetails(String authorizationDetailsJson) throws Exception;

    /**
     *
     * @return a list of AuthorizationDetails data types supported
     */
   List<String> getAuthorizationDetailsTypesSupported();

    /**
     * Merge the new AuthorizationDetailsJson with the old AuthorizationDetailsJson
     *
     * @param newAuthorizationDetailsJson
     * @param oldAuthorizationDetailsJson
     * @return an authorizationDetailsJson merged
     */
   String mergeAuthorizationDetails(String newAuthorizationDetailsJson, String oldAuthorizationDetailsJson);

    /**
     *
     * @param authorizationDetailsJson
     * @return an authorizationDetailsJson populated with some data if needed
     */
   String enrichAuthorizationDetails(String authorizationDetailsJson);
}
