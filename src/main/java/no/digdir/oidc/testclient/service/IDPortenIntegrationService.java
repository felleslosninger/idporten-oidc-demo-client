package no.digdir.oidc.testclient.service;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.IDPortenIntegrationConfiguration;
import no.digdir.oidc.testclient.crypto.KeyProvider;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.Certificate;
import java.time.Clock;
import java.util.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class IDPortenIntegrationService {

    private final IDPortenIntegrationConfiguration eidIntegrationConfiguration;
    private final Optional<KeyProvider> keyProvider;
    private final IDTokenValidator idTokenValidator;

    public AuthenticationRequest process(PushedAuthorizationRequest pushedAuthorizationRequest, CodeVerifier codeVerifier) {
        try {
            AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(
                    new ResponseType(ResponseType.Value.CODE),
                    new Scope(eidIntegrationConfiguration.getScopes().stream().toArray(String[]::new)),
                    new ClientID(eidIntegrationConfiguration.getClientId()),
                    eidIntegrationConfiguration.getRedirectUri());
            requestBuilder
                    .endpointURI(eidIntegrationConfiguration.getAuthorizationEndpoint())
                    .state(new State())
                    .nonce(new Nonce())
                    .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                    // TODO
//                    .uiLocales(Collections.singletonList(new LangTag(pushedAuthorizationRequest.getResolvedUiLocale())))
                    .prompt(new Prompt(Prompt.Type.LOGIN));
            eidIntegrationConfiguration.getCustomParameters().forEach(requestBuilder::customParameter);
            return requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    public IDToken process(AuthorizationResponse authorizationResponse, State state, Nonce nonce, CodeVerifier codeVerifier) {
        if (!Objects.equals(state, authorizationResponse.getState())) {
            throw new RuntimeException("Invalid state. State does not match state from original request."); // TODO
        }
        try {
            if (authorizationResponse.indicatesSuccess()) {
                AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationResponse.toSuccessResponse().getAuthorizationCode(), eidIntegrationConfiguration.getRedirectUri(), codeVerifier);
                final ClientAuthentication clientAuth = clientAuthentication(eidIntegrationConfiguration);
                com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(eidIntegrationConfiguration.getTokenEndpoint(), clientAuth, codeGrant);
                com.nimbusds.oauth2.sdk.TokenResponse tokenResponse = process(tokenRequest);
                if (tokenResponse.indicatesSuccess()) {
                    OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
                    IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(successResponse.getOIDCTokens().getIDToken(), nonce);
                    String personIdentifier = idTokenClaimsSet.getStringClaim(eidIntegrationConfiguration.getIdTokenConfig().getPersonIdentifierClaim());
                    return new IDToken(personIdentifier, idTokenClaimsSet);
                } else {
                    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                    log.warn("Error response from {}: {}", eidIntegrationConfiguration.getTokenEndpoint(), errorResponse.toJSONObject().toJSONString());
                    throw new RuntimeException();
                }
            } else {
                AuthorizationErrorResponse errorResponse = authorizationResponse.toErrorResponse();
                String error = errorResponse.getErrorObject().getCode();
                if (eidIntegrationConfiguration.getCancelErrorCodes().contains(error)) {
                    log.info("User cancel response from {}: {}", eidIntegrationConfiguration.getAuthorizationEndpoint(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                    throw new RuntimeException();
                }
                log.warn("Error response from {}: {}", eidIntegrationConfiguration.getAuthorizationEndpoint(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                throw new RuntimeException();

            }
        } catch (Exception e) {
            log.error("Failed to retrieve tokens from {}", eidIntegrationConfiguration.getTokenEndpoint(), e);
            throw new RuntimeException();
        }
    }

    protected ClientAuthentication clientAuthentication(IDPortenIntegrationConfiguration eidIntegrationConfiguration) {
        ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.parse(eidIntegrationConfiguration.getClientAuthMethod());
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC == clientAuthenticationMethod) {
            return new ClientSecretBasic(new ClientID(eidIntegrationConfiguration.getClientId()), new Secret(eidIntegrationConfiguration.getClientSecret()));
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST == clientAuthenticationMethod) {
            return new ClientSecretPost(new ClientID(eidIntegrationConfiguration.getClientId()), new Secret(eidIntegrationConfiguration.getClientSecret()));
        }
        if (ClientAuthenticationMethod.PRIVATE_KEY_JWT == clientAuthenticationMethod) {
            return clientAssertion(eidIntegrationConfiguration, keyProvider.get());
        }
        throw new IllegalStateException(String.format("Unknown client authentication method %s", clientAuthenticationMethod));
    }

    protected ClientAuthentication clientAssertion(IDPortenIntegrationConfiguration eidIntegrationConfiguration, KeyProvider keyProvider) {
        try {
            List<Base64> encodedCertificates = new ArrayList<>();
            for (Certificate c : keyProvider.certificateChain()) {
                encodedCertificates.add(Base64.encode(c.getEncoded()));
            }
            JWSHeader header = new JWSHeader
                    .Builder(JWSAlgorithm.RS256)
                    .x509CertChain(encodedCertificates)
                    .build();
            long created = Clock.systemUTC().millis();
            long expires = created + (120 * 1000L);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(eidIntegrationConfiguration.getClientId())
                    .subject(eidIntegrationConfiguration.getClientId())
                    .audience(eidIntegrationConfiguration.getIssuer().toString())
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(new Date(created))
                    .expirationTime(new Date(expires))
                    .build();
            JWSSigner signer = new RSASSASigner(keyProvider.privateKey());
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(signer);
            return new PrivateKeyJWT(signedJWT);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    protected void validateIDTokenClaims(IDTokenClaimsSet idTokenClaimsSet) {
        String persinIdentifier = idTokenClaimsSet.getStringClaim(eidIntegrationConfiguration.getIdTokenConfig().getPersonIdentifierClaim());
        if (persinIdentifier == null || persinIdentifier.isEmpty()) {
            throw new IllegalArgumentException(String.format("Missing value for person identifier claim %s in id_token.", eidIntegrationConfiguration.getIdTokenConfig().getPersonIdentifierClaim()));
        }
        eidIntegrationConfiguration.getIdTokenConfig().getRequiredClaims().forEach((claim, expectedValue) -> {
            String value = idTokenClaimsSet.getStringClaim(claim);
            if (! Objects.equals(value, expectedValue)) {
                throw new IllegalArgumentException(String.format("Invalid value %s for claim %s in id_token, expected %s.", value, claim, expectedValue));
            }
        });
    }

    protected TokenResponse process(com.nimbusds.oauth2.sdk.TokenRequest tokenRequest) throws IOException, ParseException {
        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        httpRequest.setConnectTimeout(eidIntegrationConfiguration.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(eidIntegrationConfiguration.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        return OIDCTokenResponseParser.parse(httpResponse);
    }

}
