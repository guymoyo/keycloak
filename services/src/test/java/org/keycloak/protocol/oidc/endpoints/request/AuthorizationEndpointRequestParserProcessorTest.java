package org.keycloak.protocol.oidc.endpoints.request;

import org.junit.Test;

import static org.junit.Assert.*;

public class AuthorizationEndpointRequestParserProcessorTest {

    private final AuthorizationEndpointRequestParserProcessor processor = new AuthorizationEndpointRequestParserProcessor();

    @Test(expected = RuntimeException.class)
    public void getRequestUriType_null() {
        // When
        processor.getRequestUriType(null);
    }

    @Test
    public void getRequestUriType_parType() {
        // When
        RequestUriType actual = processor.getRequestUriType("urn:ietf:params:oauth:request_uri:testuri");

        // Then
        assertEquals(RequestUriType.PAR, actual);
    }

    @Test
    public void getRequestUriType_requestObjectType() {
        // When
        RequestUriType actual = processor.getRequestUriType("http://www.test-env.com/redirect");

        // Then
        assertEquals(RequestUriType.REQUEST_OBJECT, actual);
    }

}