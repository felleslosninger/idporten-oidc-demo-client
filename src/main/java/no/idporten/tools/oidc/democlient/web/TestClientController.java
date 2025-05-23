package no.idporten.tools.oidc.democlient.web;


import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.idporten.tools.oidc.democlient.config.FeatureSwitchProperties;
import no.idporten.tools.oidc.democlient.config.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.config.ThemeProperties;
import no.idporten.tools.oidc.democlient.service.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Objects;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(path = "")
public class TestClientController {


    private final OIDCIntegrationService oidcIntegrationService;
    private final OIDCIntegrationProperties idPortenIntegrationConfiguration;
    private final HtmlFormService htmlFormService;
    private final ThemeProperties themeProperties;
    private final FeatureSwitchProperties featureSwitchProperties;
    private final ProtocolTracerService protocolTracerService;

    @ModelAttribute
    public void addCommonModelAttributes(Model model) {
        model.addAttribute("theme", themeProperties);
        model.addAttribute("features", featureSwitchProperties);
    }

    @GetMapping("/")
    public String index(HttpServletRequest request, Model model) {
        ProtocolTracerService.create(request.getSession());
        model.addAttribute("authorizationRequest", AuthorizationRequest.builder()
                .scope(themeProperties.getFormDefaults().getScope())
                .acrValue(themeProperties.getFormDefaults().getAcrValue())
                .uiLocale(themeProperties.getFormDefaults().getUiLocale())
                .state(new State().getValue())
                .nonce(new Nonce().getValue())
                .codeVerifier(new CodeVerifier().getValue())
                .codeChallengeMethod(CodeChallengeMethod.S256.getValue())
        .build());
        return "index";
    }

    @PostMapping("/authorize")
    public String authorize(@ModelAttribute AuthorizationRequest authorizationRequest,  HttpServletRequest request, Model model) {
        if (StringUtils.hasText(authorizationRequest.getCodeVerifier())) {
            request.getSession().setAttribute("code_verifier", new CodeVerifier(authorizationRequest.getCodeVerifier()));
        }
        com.nimbusds.oauth2.sdk.AuthorizationRequest authenticationRequest = oidcIntegrationService.authorizationRequest(authorizationRequest);
        request.getSession().setAttribute("state", new State(authorizationRequest.getState()));
        if (StringUtils.hasText(authorizationRequest.getNonce())) {
            request.getSession().setAttribute("nonce", new Nonce(authorizationRequest.getNonce()));
        }
        protocolTracerService.traceAuthorizationRequest(request.getSession(), authenticationRequest.toURI());

        model.addAttribute("uri", authenticationRequest.toURI().toString());
        return "authorize";
    }

    @GetMapping("/callback")
    public String callback(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        URI authorizationResponseUri = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getRedirectUri()).query(request.getQueryString()).build().toUri();
        protocolTracerService.traceAuthorizationResponse(request.getSession(), authorizationResponseUri);
        AuthorizationResponse authorizationResponse = oidcIntegrationService.parseAuthorizationResponse(authorizationResponseUri);
        final State state = (State) request.getSession().getAttribute("state");
        if (!Objects.equals(state, authorizationResponse.getState())) {
            throw new OIDCIntegrationException("Invalid state. Authorization response state does not match state from authorization request.");
        }
        if (authorizationResponse.indicatesSuccess()) {
            final Nonce nonce = (Nonce) request.getSession().getAttribute("nonce");
            final CodeVerifier codeVerifier = (CodeVerifier) request.getSession().getAttribute("code_verifier");
            AccessTokenResponse tokenResponse = oidcIntegrationService.token(authorizationResponse.toSuccessResponse(), state, nonce, codeVerifier);
            AccessToken accessToken = tokenResponse.getTokens().getAccessToken();
            if (accessToken != null && accessToken.getScope() != null && accessToken.getScope().contains("openid")) {
                OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
                protocolTracerService.traceValidatedIdToken(request.getSession(), oidcTokenResponse.getOIDCTokens().getIDToken());
                request.getSession().setAttribute("id_token", oidcTokenResponse.getOIDCTokens().getIDToken());
                model.addAttribute("personIdentifier",  oidcTokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim(themeProperties.getUserIdClaim()));
            }
            if (tokenResponse.getTokens().getAccessToken() != null) {
                protocolTracerService.traceBearerAccessToken(request.getSession(), accessToken.getValue());
                if (accessToken.getScope() != null && accessToken.getScope().contains("profile")) {
                    oidcIntegrationService.userinfo(accessToken);
                }
            }
            return "idtoken";
        } else {
            log.warn("Error authorization response: {}", authorizationResponse.toErrorResponse().getErrorObject().toJSONObject().toJSONString());
            return "error";
        }
    }

    @GetMapping("/logout")
    @ResponseBody
    public String logout(HttpServletRequest request) {
        JWT idToken = (JWT) request.getSession().getAttribute("id_token");
        request.getSession().invalidate();
        LogoutRequest logoutRequest =  oidcIntegrationService.logoutRequest(idToken);
        request.getSession(true);
        request.getSession().setAttribute("state", logoutRequest.getState());
        String htmlFormPage = htmlFormService.createHtmlFormAutosubmitPage(logoutRequest.getEndpointURI(), logoutRequest.toParameters());
        protocolTracerService.traceLogoutRequest(request.getSession(), htmlFormPage);
        return htmlFormPage;
    }

    @GetMapping("/logout/callback")
    public String logoutCallback(HttpServletRequest request, @RequestParam(name = "state", required = false) State state) {
        URI logoutResponse = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getPostLogoutRedirectUri()).query(request.getQueryString()).build().toUri();
        ProtocolTrace protocolTrace = protocolTracerService.traceLogoutResponse(request.getSession(), logoutResponse);
        try {
            if (request.getSession().getAttribute("state") != null && !Objects.equals(state, request.getSession().getAttribute("state"))) {
                throw new OIDCIntegrationException("Invalid state. Logout response state does not match state from logout request.");
            }
            return "logout";
        } finally {
            request.getSession().invalidate();
            request.getSession(true);
            ProtocolTracerService.set(request.getSession(), protocolTrace);
        }
    }

    @GetMapping("/logout/frontchannel")
    public String frontChannelLogout(HttpServletRequest request) {
        URI frontChannelLogoutRequest = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getFrontChannelLogoutUri()).query(request.getQueryString()).build().toUri();
        log.info("Front channel logout request: {}", frontChannelLogoutRequest);
        request.getSession().invalidate();
        ProtocolTrace protocolTrace = protocolTracerService.traceFrontChannelLogoutRequest(request.getSession(true), frontChannelLogoutRequest);
        ProtocolTracerService.set(request.getSession(), protocolTrace);
        return "logout";
    }

    @GetMapping("/trace")
    public String currentProtocolTrace() {
        return "trace";
    }

    @GetMapping("/trace/clear")
    public String clearProtocolTrace(HttpSession session) {
        ProtocolTracerService.create(session);
        return "trace";
    }

    @ExceptionHandler
    public String handleException(Exception e, Model model) {
        addCommonModelAttributes(model);
        log.error("Request handling failed", e);
        return "error";
    }

    @ExceptionHandler
    public String handleExcepion(OIDCIntegrationException e, Model model) {
        addCommonModelAttributes(model);
        model.addAttribute("message", e.getMessage());
        return "error";
    }

}
