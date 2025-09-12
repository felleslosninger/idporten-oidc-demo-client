package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpSession;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class ProtocolTrackerServiceTest {

    @InjectMocks
    private ProtocolTracerService protocolTracerService;

    @Nested
    @DisplayName("When handling a protocol trace")
    class TraceObjectHandlingTests {

        @Test
        @DisplayName("then a protocol trace can be bound to the HTTP session")
        public void testGetOrCreate() {
            MockHttpSession session = new MockHttpSession();
            assertNull(ProtocolTracerService.get(session));
            ProtocolTrace protocolTrace = ProtocolTracerService.getOrCreate(session);
            assertAll(
                    () -> assertNotNull(protocolTrace),
                    () -> assertEquals(protocolTrace, ProtocolTracerService.getOrCreate(session))
            );
        }
    }

    @Nested
    @DisplayName("When tracing login")
    class TraceLoginTests {

        private TokenRequest tokenRequest(ClientAuthentication clientAuthentication) {
            TokenRequest tokenRequest = new TokenRequest(URI.create("https://junit.idporten.no/token"), clientAuthentication,
                    new AuthorizationCodeGrant(new AuthorizationCode("ccc"), URI.create("https://junit.idporten.no/client/redirect")));
            return tokenRequest;
        }

        private TokenRequest tokenRequest() {
            ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("client"), new Secret("secret"));
            TokenRequest tokenRequest = new TokenRequest(URI.create("https://junit.idporten.no/token"), clientAuthentication,
                    new AuthorizationCodeGrant(new AuthorizationCode("ccc"), URI.create("https://junit.idporten.no/client/redirect")));
            return tokenRequest;
        }

        private HTTPResponse httpResponse() {
            HTTPResponse httpResponse = new HTTPResponse(200);
            httpResponse.setContent("foo");
            return httpResponse;
        }

        @Test
        @DisplayName("then authorization interaction is before token interaction")
        public void testTraceLoginInteractions() {
            MockHttpSession session = new MockHttpSession();
            protocolTracerService.traceAuthorizationRequest(session, URI.create("https://junit.idporten.no/authorize"));
            protocolTracerService.traceAuthorizationResponse(session, URI.create("https://junit.idporten.no/callback"));
            protocolTracerService.traceTokenRequest(session, tokenRequest().toHTTPRequest());
            protocolTracerService.traceTokenResponse(session, httpResponse());
            ProtocolTrace protocolTrace = ProtocolTracerService.get(session);
            assertAll(
                    () -> assertEquals(4, protocolTrace.getLoginInteraction().size()),
                    () -> assertEquals("https://junit.idporten.no/authorize", protocolTrace.getLoginInteraction().get(0).getInteraction()),
                    () -> assertEquals("https://junit.idporten.no/callback", protocolTrace.getLoginInteraction().get(1).getInteraction()),
                    () -> assertTrue(protocolTrace.getLoginInteraction().get(2).getInteraction().startsWith("POST https://junit.idporten.no/token")),
                    () -> assertTrue(protocolTrace.getLoginInteraction().get(3).getInteraction().contains("foo"))
            );
        }


        @Test
        @DisplayName("then client secret is masked in token request Basic Authorization header")
        public void testAuthorizationBasicAuth() {
            MockHttpSession session = new MockHttpSession();
            ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("client"), new Secret("secret"));
            TokenRequest tokenRequest = tokenRequest(clientAuthentication);
            ProtocolTrace protocolTrace = protocolTracerService.traceTokenRequest(session, tokenRequest.toHTTPRequest());
            assertAll(
                    () -> assertNotNull(protocolTrace.getTokenRequest()),
                    () -> assertTrue(protocolTrace.getTokenRequest().getInteraction().contains("Authorization: Basic ***")),
                    () -> assertFalse(protocolTrace.getTokenRequest().getInteraction().contains("secret"))
            );
        }

        @Test
        @DisplayName("then client secret is masked in token request body")
        public void testMaskClientSecretParameter() {
            MockHttpSession session = new MockHttpSession();
            ClientAuthentication clientAuthentication = new ClientSecretPost(new ClientID("client"), new Secret("secretxxx"));
            TokenRequest tokenRequest = tokenRequest(clientAuthentication);
            ProtocolTrace protocolTrace = protocolTracerService.traceTokenRequest(session, tokenRequest.toHTTPRequest());
            assertAll(
                    () -> assertNotNull(protocolTrace.getTokenRequest()),
                    () -> assertTrue(protocolTrace.getTokenRequest().getInteraction().contains("client_secret=***")),
                    () -> assertFalse(protocolTrace.getTokenRequest().getInteraction().contains("secretxxx"))
            );
        }

        @Test
        @DisplayName("then client assertion is masked in back channel endpoint request body")
        public void testMaskClientAssertionSignature() throws Exception {
            MockHttpSession session = new MockHttpSession();
            ClientSecretJWT clientAuthentication = new ClientSecretJWT(new ClientID("c1"), URI.create("https://junit.idporten.no"), JWSAlgorithm.HS256, new Secret());
            TokenRequest tokenRequest = tokenRequest(clientAuthentication);
            ProtocolTrace protocolTrace = protocolTracerService.traceTokenRequest(session, tokenRequest.toHTTPRequest());
            assertAll(
                    () -> assertNotNull(protocolTrace.getTokenRequest()),
                    () -> assertTrue(protocolTrace.getTokenRequest().getInteraction().contains("client_assertion=")),
                    () -> assertFalse(protocolTrace.getTokenRequest().getInteraction().contains(clientAuthentication.getClientAssertion().serialize()))
            );
        }
    }

    @Nested
    @DisplayName("When tracing logout")
    class TraceLogoutTests {

        @Test
        @DisplayName("then logout request is before logout response")
        public void testTraceLogoutInteractions() {
            MockHttpSession session = new MockHttpSession();
            protocolTracerService.traceLogoutRequest(session, URI.create("https://junit.idporten.no/logout"));
            protocolTracerService.traceLogoutResponse(session, URI.create("https://junit.idporten.no/logout/callback"));
            ProtocolTrace protocolTrace = ProtocolTracerService.get(session);
            assertAll(
                    () -> assertEquals(2, protocolTrace.getLogoutInteraction().size()),
                    () -> assertEquals("https://junit.idporten.no/logout", protocolTrace.getLogoutInteraction().get(0).getInteraction()),
                    () -> assertEquals("https://junit.idporten.no/logout/callback", protocolTrace.getLogoutInteraction().get(1).getInteraction())
            );

        }
    }

}
