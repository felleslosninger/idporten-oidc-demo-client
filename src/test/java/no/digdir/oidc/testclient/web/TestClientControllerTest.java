package no.digdir.oidc.testclient.web;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.State;
import no.digdir.oidc.testclient.config.OIDCIntegrationProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpSession;
import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
public class TestClientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OIDCIntegrationProperties oidcIntegrationProperties;

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
        @DisplayName("then valid logout response gives the logout view")
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

    }

}
