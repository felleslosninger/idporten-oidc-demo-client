package no.digdir.oidc.testclient.web;

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
    @Singular("acrValue")
    private List<String> acrValues = new ArrayList<>();
    @Singular("uiLocale")
    private List<String> uiLocales = new ArrayList<>();
    private String state;
    private String nonce;
    private String codeVerifier;
    private String codeChallengeMethod;

}
