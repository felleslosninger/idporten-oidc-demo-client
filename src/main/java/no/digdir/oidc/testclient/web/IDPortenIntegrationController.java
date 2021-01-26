package no.digdir.oidc.testclient.web;


import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.IDPortenIntegrationConfiguration;
import no.digdir.oidc.testclient.service.IDPortenIntegrationService;
import no.digdir.oidc.testclient.service.IDToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URI;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping(path = "")
public class IDPortenIntegrationController {


    private final IDPortenIntegrationService eidIntegrationService;
    private final IDPortenIntegrationConfiguration idPortenIntegrationConfiguration;

    public String index(Model model) {
        return "index";
    }


    @PostMapping("/authorize")
    public String authorize(HttpServletRequest request) {
        CodeVerifier codeVerifier = new CodeVerifier();
        AuthenticationRequest authenticationRequest = eidIntegrationService.process(null, codeVerifier);
        request.getSession().setAttribute("state", authenticationRequest.getState());
        request.getSession().setAttribute("nonce", authenticationRequest.getNonce());
        request.getSession().setAttribute("codeVerifier", codeVerifier);
        return "redirect:" + authenticationRequest.toURI().toString();
    }

    @GetMapping("/callback")
    public String callback(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
        URI authorizationResponseUri = UriComponentsBuilder.fromUri(idPortenIntegrationConfiguration.getRedirectUri()).query(request.getQueryString()).build().toUri();
        com.nimbusds.oauth2.sdk.AuthorizationResponse authorizationResponse = com.nimbusds.oauth2.sdk.AuthorizationResponse.parse(authorizationResponseUri);
        final State state = (State) request.getSession().getAttribute("state");
        final Nonce nonce = (Nonce) request.getSession().getAttribute("nonce");
        final CodeVerifier codeVerifier = (CodeVerifier) request.getSession().getAttribute("code_verifier");
        IDToken idToken = eidIntegrationService.process(authorizationResponse, state, nonce, codeVerifier);
        return "authenticated";

    }

}
