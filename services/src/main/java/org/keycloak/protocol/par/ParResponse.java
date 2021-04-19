package org.keycloak.protocol.par;

public class ParResponse {

    private String request_uri;
    private String expires_in;

    public ParResponse(String requestUri, String expiresIn) {
        this.request_uri = requestUri;
        this.expires_in = expiresIn;
    }

    public String getRequestUri() {
        return request_uri;
    }

    public void setRequestUri(String requestUri) {
        this.request_uri = requestUri;
    }

    public String getExpiresIn() {
        return expires_in;
    }

    public void setExpiresIn(String expiresIn) {
        this.expires_in = expiresIn;
    }
}
