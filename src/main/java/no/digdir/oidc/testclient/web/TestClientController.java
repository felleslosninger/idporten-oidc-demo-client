package no.digdir.oidc.testclient.web;


import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.OIDCIntegrationProperties;
import no.digdir.oidc.testclient.service.OIDCIntegrationService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(path = "")
public class TestClientController {


    private final OIDCIntegrationService oidcIntegrationService;
    private final OIDCIntegrationProperties idPortenIntegrationConfiguration;

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("authorizationRequest", AuthorizationRequest.builder()
                .scope("openid")
                .acrValue("Level3")
                .uiLocale("nb")
                .state(new State().getValue())
                .nonce(new Nonce().getValue())
                .codeVerifier(new CodeVerifier().getValue())
                .codeChallengeMethod(CodeChallengeMethod.S256.getValue())
        .build());
        return "index";
    }

    @PostMapping("/authorize")
    public String authorize(@ModelAttribute AuthorizationRequest authorizationRequest,  HttpServletRequest request) {
        request.getSession().setAttribute("codeVerifier", new CodeVerifier(authorizationRequest.getCodeVerifier()));
        AuthenticationRequest authenticationRequest = oidcIntegrationService.process(authorizationRequest);
        request.getSession().setAttribute("state", authenticationRequest.getState());
        request.getSession().setAttribute("nonce", authenticationRequest.getNonce());
        return "redirect:" + authenticationRequest.toURI().toString();
    }

    @GetMapping("/callback")
    public String callback(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        URI authorizationResponseUri = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getRedirectUri()).query(request.getQueryString()).build().toUri();
        com.nimbusds.oauth2.sdk.AuthorizationResponse authorizationResponse = com.nimbusds.oauth2.sdk.AuthorizationResponse.parse(authorizationResponseUri);
        final State state = (State) request.getSession().getAttribute("state");
        final Nonce nonce = (Nonce) request.getSession().getAttribute("nonce");
        final CodeVerifier codeVerifier = (CodeVerifier) request.getSession().getAttribute("code_verifier");
        OIDCTokenResponse oidcTokenResponse = oidcIntegrationService.process(authorizationResponse, state, nonce, codeVerifier);
        model.addAttribute("idTokenClaims", oidcTokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaims());
        return "idtoken";
    }

}
