package org.keycloak.protocol.oidc.par;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ParResponse {

    @JsonProperty("request_uri")
    private String requestUri;

    @JsonProperty("expires_in")
    private String expiresIn;

    public ParResponse(String requestUri, String expiresIn) {
        this.requestUri = requestUri;
        this.expiresIn = expiresIn;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }
}
