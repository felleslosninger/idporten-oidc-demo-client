package no.digdir.oidc.testclient.web;


import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.OIDCIntegrationProperties;
import no.digdir.oidc.testclient.service.OIDCIntegrationException;
import no.digdir.oidc.testclient.service.OIDCIntegrationService;
import no.digdir.oidc.testclient.service.ProtocolTrace;
import no.digdir.oidc.testclient.service.ProtocolTracerService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Objects;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(path = "")
public class TestClientController {


    private final OIDCIntegrationService oidcIntegrationService;
    private final OIDCIntegrationProperties idPortenIntegrationConfiguration;
    private final ProtocolTracerService protocolTracerService;

    @GetMapping("/")
    public String index(HttpServletRequest request, Model model) {
        ProtocolTracerService.create(request.getSession());
        model.addAttribute("authorizationRequest", AuthorizationRequest.builder()
                .scope("openid")
                .acrValue("low")
                .uiLocale("en")
                .state(new State().getValue())
                .nonce(new Nonce().getValue())
                .codeVerifier(new CodeVerifier().getValue())
                .codeChallengeMethod(CodeChallengeMethod.S256.getValue())
        .build());
        return "index";
    }

    @PostMapping("/authorize")
    public String authorize(@ModelAttribute AuthorizationRequest authorizationRequest,  HttpServletRequest request) {
        if (StringUtils.hasText(authorizationRequest.getCodeVerifier())) {
            request.getSession().setAttribute("code_verifier", new CodeVerifier(authorizationRequest.getCodeVerifier()));
        }
        AuthenticationRequest authenticationRequest = oidcIntegrationService.authorzationRequest(authorizationRequest);
        request.getSession().setAttribute("state", authenticationRequest.getState());
        request.getSession().setAttribute("nonce", authenticationRequest.getNonce());
        protocolTracerService.traceAuthorizationRequest(request.getSession(), authenticationRequest.toURI());
        return "redirect:" + authenticationRequest.toURI().toString();
    }

    @GetMapping("/callback")
    public String callback(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        URI authorizationResponseUri = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getRedirectUri()).query(request.getQueryString()).build().toUri();
        protocolTracerService.traceAuthorizationResponse(request.getSession(), authorizationResponseUri);
        com.nimbusds.oauth2.sdk.AuthorizationResponse authorizationResponse = com.nimbusds.oauth2.sdk.AuthorizationResponse.parse(authorizationResponseUri);
        final State state = (State) request.getSession().getAttribute("state");
        if (!Objects.equals(state, authorizationResponse.getState())) {
            throw new OIDCIntegrationException("Invalid state. Authorization response state does not match state from authorization request.");
        }
        if (authorizationResponse.indicatesSuccess()) {
            final Nonce nonce = (Nonce) request.getSession().getAttribute("nonce");
            final CodeVerifier codeVerifier = (CodeVerifier) request.getSession().getAttribute("code_verifier");
            OIDCTokenResponse oidcTokenResponse = oidcIntegrationService.token(authorizationResponse.toSuccessResponse(), state, nonce, codeVerifier);
            protocolTracerService.traceValidatedIdToken(request.getSession(), oidcTokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet());
            if (oidcTokenResponse.getOIDCTokens().getAccessToken() != null) {
                protocolTracerService.traceBearerAccessToken(request.getSession(), oidcTokenResponse.getOIDCTokens().getAccessToken().getValue());
            }
            request.getSession().setAttribute("id_token", oidcTokenResponse.getOIDCTokens().getIDToken());
            model.addAttribute("personIdentifier",  oidcTokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getSubject());
            return "idtoken";
        } else {
            log.warn("Error authorization response: {}", authorizationResponse.toErrorResponse().getErrorObject().toJSONObject().toJSONString());
            return "error";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        JWT idToken = (JWT) request.getSession().getAttribute("id_token");
        request.getSession().invalidate();
        LogoutRequest logoutRequest =  oidcIntegrationService.logoutRequest(idToken);
        request.getSession(true);
        request.getSession().setAttribute("state", logoutRequest.getState());
        protocolTracerService.traceLogoutRequest(request.getSession(), logoutRequest.toURI());
        return "redirect:" + logoutRequest.toURI().toString();
    }

    @GetMapping("/logout/callback")
    public String logoutCallback(HttpServletRequest request, @RequestParam(name = "state", required = false) State state) {
        URI logoutResponse = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getPostLogoutRedirectUri()).query(request.getQueryString()).build().toUri();
        ProtocolTrace protocolTrace = protocolTracerService.traceLogoutResponse(request.getSession(), logoutResponse);
        try {
            if (!Objects.equals(state, request.getSession().getAttribute("state"))) {
                throw new OIDCIntegrationException("Invalid state. Logout response state does not match state from logout request.");
            }
            return "logout";
        } finally {
            request.getSession().invalidate();
            request.getSession(true);
            ProtocolTracerService.set(request.getSession(), protocolTrace);
        }
    }

    @ExceptionHandler
    public String handleExcepion(Exception e) {
        log.error("Request handling failed", e);
        return "error";
    }

    @ExceptionHandler
    public String handleExcepion(OIDCIntegrationException e, Model model) {
        model.addAttribute("message", e.getMessage());
        return "error";
    }

}
