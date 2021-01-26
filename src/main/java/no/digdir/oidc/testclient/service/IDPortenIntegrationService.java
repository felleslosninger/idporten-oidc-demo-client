package no.digdir.oidc.testclient.service;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.IDPortenIntegrationConfiguration;
import no.digdir.oidc.testclient.crypto.KeyProvider;
import no.digdir.oidc.testclient.web.AuthorizationRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.cert.Certificate;
import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Service
@RequiredArgsConstructor
public class IDPortenIntegrationService {

    private final IDPortenIntegrationConfiguration idPortenIntegrationConfiguration;
    private final Optional<KeyProvider> keyProvider;
    private final IDTokenValidator idTokenValidator;

    public AuthenticationRequest process(AuthorizationRequest authorizationRequest) {
        try {
            AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(
                    new ResponseType(ResponseType.Value.CODE),
                    new Scope(authorizationRequest.getScopes().stream().toArray(String[]::new)),
                    new ClientID(idPortenIntegrationConfiguration.getClientId()),
                    idPortenIntegrationConfiguration.getRedirectUri());
            requestBuilder
                    .endpointURI(idPortenIntegrationConfiguration.getAuthorizationEndpoint());
            if (StringUtils.hasText(authorizationRequest.getState())) {
                requestBuilder.state(new State(authorizationRequest.getState()));
            }
            if (StringUtils.hasText(authorizationRequest.getNonce())) {
                requestBuilder.nonce(new Nonce(authorizationRequest.getNonce()));
            }
            if (! CollectionUtils.isEmpty(authorizationRequest.getUiLocales())) {
                requestBuilder.uiLocales(authorizationRequest.getUiLocales().stream()
                        .map(this::langTag)
                        .filter(langTag -> langTag != null)
                        .collect(Collectors.toList()));
            }
            if (! CollectionUtils.isEmpty(authorizationRequest.getAcrValues())) {
                requestBuilder.acrValues(authorizationRequest.getAcrValues().stream()
                        .map(acr -> new ACR(acr))
                        .collect(Collectors.toList()));
            }
            if (StringUtils.hasText(authorizationRequest.getCodeVerifier())) {
                requestBuilder.codeChallenge(
                        new CodeVerifier(authorizationRequest.getCodeVerifier()),
                        new CodeChallengeMethod(authorizationRequest.getCodeChallengeMethod()));
            }
            return requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    protected LangTag langTag(String locale) {
        try {
            return new LangTag(locale);
        } catch (LangTagException e) {
            return null;
        }
    }

    public OIDCTokenResponse process(AuthorizationResponse authorizationResponse, State state, Nonce nonce, CodeVerifier codeVerifier) {
        if (!Objects.equals(state, authorizationResponse.getState())) {
            throw new RuntimeException("Invalid state. State does not match state from original request."); // TODO
        }
        try {
            if (authorizationResponse.indicatesSuccess()) {
                AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationResponse.toSuccessResponse().getAuthorizationCode(), idPortenIntegrationConfiguration.getRedirectUri(), codeVerifier);
                final ClientAuthentication clientAuth = clientAuthentication(idPortenIntegrationConfiguration);
                com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(idPortenIntegrationConfiguration.getTokenEndpoint(), clientAuth, codeGrant);
                com.nimbusds.oauth2.sdk.TokenResponse tokenResponse = process(tokenRequest);
                if (tokenResponse.indicatesSuccess()) {
                    OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
                    idTokenValidator.validate(successResponse.getOIDCTokens().getIDToken(), nonce);
                    return successResponse;
                } else {
                    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                    log.warn("Error response from {}: {}", idPortenIntegrationConfiguration.getTokenEndpoint(), errorResponse.toJSONObject().toJSONString());
                    throw new RuntimeException();
                }
            } else {
                AuthorizationErrorResponse errorResponse = authorizationResponse.toErrorResponse();
                String error = errorResponse.getErrorObject().getCode();
                if (idPortenIntegrationConfiguration.getCancelErrorCodes().contains(error)) {
                    log.info("User cancel response from {}: {}", idPortenIntegrationConfiguration.getAuthorizationEndpoint(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                    throw new RuntimeException();
                }
                log.warn("Error response from {}: {}", idPortenIntegrationConfiguration.getAuthorizationEndpoint(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                throw new RuntimeException();

            }
        } catch (Exception e) {
            log.error("Failed to retrieve tokens from {}", idPortenIntegrationConfiguration.getTokenEndpoint(), e);
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

    protected TokenResponse process(com.nimbusds.oauth2.sdk.TokenRequest tokenRequest) throws IOException, ParseException {
        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        httpRequest.setConnectTimeout(idPortenIntegrationConfiguration.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(idPortenIntegrationConfiguration.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        return OIDCTokenResponseParser.parse(httpResponse);
    }

}
