package no.digdir.oidc.testclient.web;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import no.digdir.oidc.testclient.config.OIDCIntegrationProperties;
import no.digdir.oidc.testclient.service.ProtocolTrace;
import no.digdir.oidc.testclient.service.ProtocolTracerService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpSession;
import java.net.URI;
import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class TestClientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OIDCIntegrationProperties oidcIntegrationProperties;

    @Autowired
    private OIDCProviderMetadata oidcProviderMetadata;

    @Autowired
    private ProtocolTracerService protocolTracerService;

    @Nested
    @DisplayName("When starting to log in")
    class StartLoginTests {

        @Test
        @DisplayName("then the model is populated with default values and generated values for state, nonce and code_verifier")
        public void testLoginPage() throws Exception {
            MvcResult mvcResult = mockMvc.perform(
                    get("/"))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(view().name("index"))
                    .andExpect(model().attributeExists("authorizationRequest"))
                    .andReturn();
            AuthorizationRequest authorizationRequest = (AuthorizationRequest) mvcResult.getModelAndView().getModel().get("authorizationRequest");
            assertAll(
                    () -> assertTrue(StringUtils.hasText(authorizationRequest.getState())),
                    () -> assertTrue(StringUtils.hasText(authorizationRequest.getNonce())),
                    () -> assertTrue(StringUtils.hasText(authorizationRequest.getCodeVerifier())),
                    () -> assertEquals("openid", authorizationRequest.getScopes().get(0)),
                    () -> assertEquals("Level3", authorizationRequest.getAcrValues().get(0)),
                    () -> assertEquals("nb", authorizationRequest.getUiLocales().get(0)),
                    () -> assertEquals("S256", authorizationRequest.getCodeChallengeMethod())
            );
        }

        @Test
        @DisplayName("then redirected authorization request contains parameters with values from user input")
        public void testRedirectedAuthorizationRequest() throws Exception {
            final String state = new State().getValue();
            final String nonce = new Nonce().getValue();
            final String codeVerifier = new CodeVerifier().getValue();
            MvcResult mvcResult = mockMvc.perform(
                    post("/authorize")
                            .param("scopes", "openid")
                            .param("acrValues", "Level3")
                            .param("uiLocales", "nb")
                            .param("prompt", "login")
                            .param("state", state)
                            .param("nonce", nonce)
                            .param("codeVerifier", codeVerifier)
                            .param("codeChallengeMethod", "S256"))
                    .andExpect(status().is3xxRedirection())
                    .andReturn();
            HttpSession session = mvcResult.getRequest().getSession();
            UriComponents authorizationRequest = UriComponentsBuilder
                    .fromHttpUrl(mvcResult.getResponse().getRedirectedUrl())
                    .build();
            ProtocolTrace protocolTrace = ProtocolTracerService.get(mvcResult.getRequest().getSession());
            assertAll(
                    () -> assertEquals(oidcProviderMetadata.getAuthorizationEndpointURI().getHost(), authorizationRequest.getHost()),
                    () -> assertEquals(oidcProviderMetadata.getAuthorizationEndpointURI().getPath(), authorizationRequest.getPath()),
                    () -> assertEquals(oidcIntegrationProperties.getClientId(), authorizationRequest.getQueryParams().getFirst("client_id")),
                    () -> assertEquals(UriUtils.encode(oidcIntegrationProperties.getRedirectUri().toString(), Charset.defaultCharset()), authorizationRequest.getQueryParams().getFirst("redirect_uri")),
                    () -> assertEquals("openid", authorizationRequest.getQueryParams().getFirst("scope")),
                    () -> assertEquals("Level3", authorizationRequest.getQueryParams().getFirst("acr_values")),
                    () -> assertEquals("nb", authorizationRequest.getQueryParams().getFirst("ui_locales")),
                    () -> assertEquals("login", authorizationRequest.getQueryParams().getFirst("prompt")),
                    () -> assertEquals(state, authorizationRequest.getQueryParams().getFirst("state")),
                    () -> assertEquals(new State(state), session.getAttribute("state")),
                    () -> assertEquals(nonce, authorizationRequest.getQueryParams().getFirst("nonce")),
                    () -> assertEquals(new Nonce(nonce), session.getAttribute("nonce")),
                    () -> assertTrue(StringUtils.hasText(authorizationRequest.getQueryParams().getFirst("code_challenge"))),
                    () -> assertEquals(new CodeVerifier(codeVerifier), session.getAttribute("code_verifier")),
                    () -> assertEquals("S256", authorizationRequest.getQueryParams().getFirst("code_challenge_method")),
                    () -> assertNotNull(protocolTrace),
                    () -> assertNotNull(protocolTrace.getAuthorizationRequest())
            );
        }

    }

    @Nested
    @DisplayName("When handling successful authorization response")
    class SuccessfulAuthorizationResponseTests {

        @Test
        @DisplayName("then state values must match")
        public void testStateValuesMustMatch() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("state", new State("idaho"));
            MvcResult mvcResult = mockMvc.perform(
                    get("/callback")
                            .session(mockSession)
                            .queryParam("state", "texas")
                            .queryParam("code", "abc123"))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(view().name("error"))
                    .andReturn();
        }

    }

    @Nested
    @DisplayName("When handling error authorization response")
    class ErrorAuthorizationResponseTests {

        @Test
        @DisplayName("then state values must match")
        public void testStateValuesMustMatch() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("state", new State("idaho"));
            mockMvc.perform(
                    get("/callback")
                            .session(mockSession)
                            .queryParam("state", "texas")
                            .queryParam("error", "invalid_request"))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(view().name("error"));
            ProtocolTrace protocolTrace = ProtocolTracerService.get(mockSession);
            assertAll(
                    () -> assertNotNull(protocolTrace),
                    () -> assertNotNull(protocolTrace.getAuthorizationResponse())
            );
        }

        @Test
        @DisplayName("then error view is loaded")
        public void testHandleErrorResponse() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("state", new State("hawaii"));
            mockMvc.perform(
                    get("/callback")
                            .session(mockSession)
                            .queryParam("state", "hawaii")
                            .queryParam("error", "invalid_request"))
                    .andExpect(status().is2xxSuccessful())
                    .andExpect(view().name("error"));
        }

    }


    @Nested
    @DisplayName("When handling RP-initiated logout")
    class LogoutTests {

        @Test
        @DisplayName("then redirected logout request contains parameters id_token_hint, state and post_logout_redirect_uri")
        public void testSendLogoutRequest() throws Exception {
            JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("id_token", idToken);
            MvcResult mvcResult = mockMvc.perform(
                    get("/logout")
                            .session(mockSession))
                    .andExpect(status().is3xxRedirection())
                    .andReturn();
            HttpSession session = mvcResult.getRequest().getSession();
            UriComponents logoutRequest = UriComponentsBuilder
                    .fromHttpUrl(mvcResult.getResponse().getRedirectedUrl())
                    .build();

            assertAll(
                    () -> assertEquals(
                            idToken.serialize(),
                            logoutRequest.getQueryParams().getFirst("id_token_hint")),
                    () -> assertEquals(
                            UriUtils.encode(oidcIntegrationProperties.getPostLogoutRedirectUri().toString(), Charset.defaultCharset()),
                            logoutRequest.getQueryParams().getFirst("post_logout_redirect_uri")),
                    () -> assertEquals(String.valueOf(
                            session.getAttribute("state")),
                            logoutRequest.getQueryParams().getFirst("state")),
                    () -> assertNotNull(session.getAttribute("state"))
            );
        }

        @Test
        @DisplayName("then logout response with invalid state is rejected and gives the error view")
        public void testInvalidLogoutResponse() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockMvc.perform(
                    get("/logout/callback/")
                            .queryParam("state", "canada")
                            .session(mockSession))
                    .andExpect(view().name("error"));
            assertTrue(mockSession.isInvalid());
        }

        @Test
        @DisplayName("then valid logout response invalidates session and gives the logout view")
        public void testValidLogoutResponse() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("state", new State("alaska"));
            mockMvc.perform(
                    get("/logout/callback/")
                            .queryParam("state", "alaska")
                            .session(mockSession))
                    .andExpect(view().name("logout"));
            assertTrue(mockSession.isInvalid());
        }

        @Test
        @DisplayName("then logout request and response are traced across sessions")
        public void testTraceLogout() throws Exception {
            MockHttpSession mockSession = new MockHttpSession();
            mockSession.setAttribute("state", new State("alaska"));
            ProtocolTrace protocolTrace = ProtocolTracerService.create(mockSession);
            protocolTracerService.traceLogoutRequest(mockSession, URI.create("https://idporten.junit.no/logout"));
            MvcResult mvcResult = mockMvc.perform(
                    get("/logout/callback/")
                            .queryParam("state", "alaska")
                            .session(mockSession))
                    .andExpect(view().name("logout"))
                    .andReturn();
            assertAll(
                    () -> assertTrue(mockSession.isInvalid()),
                    () -> assertNotNull(protocolTrace.getLogoutRequest()),
                    () -> assertNotNull(protocolTrace.getLogoutResponse())
            );
        }

    }

}
