package no.digdir.oidc.testclient.service;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
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
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.OIDCIntegrationProperties;
import no.digdir.oidc.testclient.crypto.KeyProvider;
import no.digdir.oidc.testclient.web.AuthorizationRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.Certificate;
import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Service
@RequiredArgsConstructor
public class OIDCIntegrationService {

    private final OIDCIntegrationProperties oidcIntegrationProperties;
    private final Optional<KeyProvider> keyProvider;
    private final IDTokenValidator idTokenValidator;
    private final OIDCProviderMetadata oidcProviderMetadata;
    private final ProtocolTracerService oidcProtocolTracerService;

    public AuthenticationRequest authorzationRequest(AuthorizationRequest authorizationRequest) {
        try {
            AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(
                    new ResponseType(ResponseType.Value.CODE),
                    new Scope(authorizationRequest.getScopes().stream().toArray(String[]::new)),
                    new ClientID(oidcIntegrationProperties.getClientId()),
                    oidcIntegrationProperties.getRedirectUri());
            requestBuilder
                    .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI());
            if (!CollectionUtils.isEmpty(authorizationRequest.getPrompt())) {
                requestBuilder.prompt(new Prompt(authorizationRequest.getPrompt().stream().toArray(String[]::new)));
            }
            if (!CollectionUtils.isEmpty(authorizationRequest.getUiLocales())) {
                requestBuilder.uiLocales(authorizationRequest.getUiLocales().stream()
                        .map(this::langTag)
                        .filter(langTag -> langTag != null)
                        .collect(Collectors.toList()));
            }
            if (!CollectionUtils.isEmpty(authorizationRequest.getAcrValues())) {
                requestBuilder.acrValues(authorizationRequest.getAcrValues().stream()
                        .map(acr -> new ACR(acr))
                        .collect(Collectors.toList()));
            }
            if (StringUtils.hasText(authorizationRequest.getState())) {
                requestBuilder.state(new State(authorizationRequest.getState()));
            }
            if (StringUtils.hasText(authorizationRequest.getNonce())) {
                requestBuilder.nonce(new Nonce(authorizationRequest.getNonce()));
            }
            if (StringUtils.hasText(authorizationRequest.getCodeVerifier())) {
                requestBuilder.codeChallenge(
                        new CodeVerifier(authorizationRequest.getCodeVerifier()),
                        new CodeChallengeMethod(authorizationRequest.getCodeChallengeMethod()));
            }
            return requestBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected LangTag langTag(String locale) {
        try {
            return new LangTag(locale);
        } catch (LangTagException e) {
            return null;
        }
    }

    public OIDCTokenResponse token(AuthorizationResponse authorizationResponse, State state, Nonce nonce, CodeVerifier codeVerifier) {
        if (!Objects.equals(state, authorizationResponse.getState())) {
            throw new RuntimeException("Invalid state. State does not match state from original request."); // TODO
        }
        try {
            if (authorizationResponse.indicatesSuccess()) {
                AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationResponse.toSuccessResponse().getAuthorizationCode(), oidcIntegrationProperties.getRedirectUri(), codeVerifier);
                final ClientAuthentication clientAuth = clientAuthentication(oidcIntegrationProperties);
                com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(oidcProviderMetadata.getTokenEndpointURI(), clientAuth, codeGrant);
                com.nimbusds.oauth2.sdk.TokenResponse tokenResponse = process(tokenRequest);
                if (tokenResponse.indicatesSuccess()) {
                    OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
                    idTokenValidator.validate(successResponse.getOIDCTokens().getIDToken(), nonce);
                    return successResponse;
                } else {
                    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                    log.warn("Error response from {}: {}", oidcProviderMetadata.getTokenEndpointURI(), errorResponse.toJSONObject().toJSONString());
                    throw new RuntimeException();
                }
            } else {
                AuthorizationErrorResponse errorResponse = authorizationResponse.toErrorResponse();
                log.warn("Error response from {}: {}", oidcProviderMetadata.getAuthorizationEndpointURI(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                throw new RuntimeException();
            }
        } catch (Exception e) {
            log.error("Failed to retrieve tokens from {}", oidcProviderMetadata.getTokenEndpointURI(), e);
            throw new RuntimeException();
        }
    }

    public LogoutRequest logoutRequest(JWT idToken) {
        return new LogoutRequest(
                oidcProviderMetadata.getEndSessionEndpointURI(),
                idToken,
                oidcIntegrationProperties.getPostLogoutRedirectUri(),
                new State());
    }

    protected ClientAuthentication clientAuthentication(OIDCIntegrationProperties oidcIntegrationProperties) {
        ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.parse(oidcIntegrationProperties.getClientAuthMethod());
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC == clientAuthenticationMethod) {
            return new ClientSecretBasic(new ClientID(oidcIntegrationProperties.getClientId()), new Secret(oidcIntegrationProperties.getClientSecret()));
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST == clientAuthenticationMethod) {
            return new ClientSecretPost(new ClientID(oidcIntegrationProperties.getClientId()), new Secret(oidcIntegrationProperties.getClientSecret()));
        }
        if (ClientAuthenticationMethod.PRIVATE_KEY_JWT == clientAuthenticationMethod) {
            return clientAssertion(oidcIntegrationProperties, keyProvider.get());
        }
        throw new IllegalStateException(String.format("Unknown client authentication method %s", clientAuthenticationMethod));
    }

    protected ClientAuthentication clientAssertion(OIDCIntegrationProperties oidcIntegrationProperties, KeyProvider keyProvider) {
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
                    .issuer(oidcIntegrationProperties.getClientId())
                    .subject(oidcIntegrationProperties.getClientId())
                    .audience(oidcIntegrationProperties.getIssuer().toString())
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
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        oidcProtocolTracerService.traceTokenRequest(request.getSession(), httpRequest);
        httpRequest.setConnectTimeout(oidcIntegrationProperties.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(oidcIntegrationProperties.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        oidcProtocolTracerService.traceTokenResponse(request.getSession(), httpResponse);
        return OIDCTokenResponseParser.parse(httpResponse);
    }

}
