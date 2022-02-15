package no.idporten.tools.oidc.democlient.web;

import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationRequest {

    @Singular("scope")
    private List<String> scopes = new ArrayList<>();
    private String authorizationDetails;
    @Singular("acrValue")
    private List<String> acrValues = new ArrayList<>();
    @Singular("uiLocale")
    private List<String> uiLocales = new ArrayList<>();
    private List<String> prompt;
    private String state;
    private String nonce;
    private String codeVerifier;
    private String codeChallengeMethod;

}
