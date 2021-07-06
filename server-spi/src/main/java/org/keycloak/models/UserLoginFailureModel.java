/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models;

import org.keycloak.storage.SearchableModelField;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface UserLoginFailureModel {

   class SearchableFields {
      public static final SearchableModelField<UserLoginFailureModel> ID       = new SearchableModelField<>("id", String.class);
      public static final SearchableModelField<UserLoginFailureModel> REALM_ID = new SearchableModelField<>("realmId", String.class);
      public static final SearchableModelField<UserLoginFailureModel> USER_ID  = new SearchableModelField<>("userId", String.class);
   }

   String getId();
   String getUserId();
   int getFailedLoginNotBefore();
   void setFailedLoginNotBefore(int notBefore);
   int getNumFailures();
   void incrementFailures();
   void clearFailures();
   long getLastFailure();
   void setLastFailure(long lastFailure);
   String getLastIPFailure();
   void setLastIPFailure(String ip);


}
