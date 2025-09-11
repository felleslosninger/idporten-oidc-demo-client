package no.idporten.tools.oidc.democlient.service;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
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
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.idporten.tools.oidc.democlient.config.FeatureSwitchProperties;
import no.idporten.tools.oidc.democlient.config.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.crypto.KeyProvider;
import no.idporten.tools.oidc.democlient.web.AuthorizationRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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
    private final JARMValidator jarmValidator;
    private final OIDCProviderMetadata oidcProviderMetadata;
    private final ProtocolTracerService oidcProtocolTracerService;
    private final FeatureSwitchProperties featureSwitchProperties;
    private final CertChainValidator certChainValidator;
    private final RemoteJWKSet remoteJWKSet;

    public com.nimbusds.oauth2.sdk.AuthorizationRequest authorizationRequest(AuthorizationRequest authorizationRequest) {
        try {
            final com.nimbusds.oauth2.sdk.AuthorizationRequest request;
            if (authorizationRequest.getScopes().contains("openid")) {
                request = oidcAuthorizationRequest(authorizationRequest);
            } else {
                request = oauth2AuthorizationRequest(authorizationRequest);
            }
            if (featureSwitchProperties.isUsePushedAuthorizationRequests()) {
                return pushAuthorizationRequest(request);
            }
            return request;
        } catch (OIDCIntegrationException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected com.nimbusds.oauth2.sdk.AuthorizationRequest oauth2AuthorizationRequest(AuthorizationRequest authorizationRequest) {
        com.nimbusds.oauth2.sdk.AuthorizationRequest.Builder requestBuilder = new com.nimbusds.oauth2.sdk.AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new ClientID(oidcIntegrationProperties.getClientId()));
        requestBuilder.scope(new Scope(authorizationRequest.getScopes().toArray(String[]::new)))
                .redirectionURI(oidcIntegrationProperties.getRedirectUri())
                .responseMode(oidcIntegrationProperties.getResponseMode())
                .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI());

        if (featureSwitchProperties.isAuthorizationDetailsEnabled() && StringUtils.hasText(authorizationRequest.getAuthorizationDetails())) {
            requestBuilder.customParameter("authorization_details", authorizationRequest.getAuthorizationDetails());
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getPrompt())) {
            requestBuilder.prompt(new Prompt(authorizationRequest.getPrompt().toArray(String[]::new)));
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getUiLocales())) {
            requestBuilder.customParameter("ui_locales", authorizationRequest.getUiLocales().toArray(String[]::new));
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getAcrValues())) {
            requestBuilder.customParameter("acr_values", authorizationRequest.getAcrValues().toArray(String[]::new));
        }
        if (StringUtils.hasText(authorizationRequest.getState())) {
            requestBuilder.state(new State(authorizationRequest.getState()));
        }
        if (StringUtils.hasText(authorizationRequest.getCodeVerifier())) {
            requestBuilder.codeChallenge(
                    new CodeVerifier(authorizationRequest.getCodeVerifier()),
                    new CodeChallengeMethod(authorizationRequest.getCodeChallengeMethod()));
        }
        return requestBuilder.build();
    }

    protected AuthenticationRequest oidcAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope(authorizationRequest.getScopes().toArray(String[]::new)),
                new ClientID(oidcIntegrationProperties.getClientId()),
                oidcIntegrationProperties.getRedirectUri());
        requestBuilder
                .responseMode(oidcIntegrationProperties.getResponseMode())
                .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI());
        if (featureSwitchProperties.isAuthorizationDetailsEnabled() && StringUtils.hasText(authorizationRequest.getAuthorizationDetails())) {
            requestBuilder.customParameter("authorization_details", authorizationRequest.getAuthorizationDetails());
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getPrompt())) {
            requestBuilder.prompt(new Prompt(authorizationRequest.getPrompt().toArray(String[]::new)));
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getUiLocales())) {
            requestBuilder.uiLocales(authorizationRequest.getUiLocales().stream()
                    .map(this::langTag)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList()));
        }
        if (!CollectionUtils.isEmpty(authorizationRequest.getAcrValues())) {
            requestBuilder.acrValues(authorizationRequest.getAcrValues().stream()
                    .map(ACR::new)
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
    }

    protected LangTag langTag(String locale) {
        try {
            return new LangTag(locale);
        } catch (LangTagException e) {
            return null;
        }
    }


    public com.nimbusds.oauth2.sdk.AuthorizationRequest pushAuthorizationRequest(com.nimbusds.oauth2.sdk.AuthorizationRequest authorizationRequest) {
        try {
            PushedAuthorizationRequest pushedAuthorizationRequest = new PushedAuthorizationRequest(
                    oidcProviderMetadata.getPushedAuthorizationRequestEndpointURI(),
                    clientAuthentication(oidcIntegrationProperties),
                    authorizationRequest);
            PushedAuthorizationResponse response = process(pushedAuthorizationRequest);
            if (response.indicatesSuccess()) {
                com.nimbusds.oauth2.sdk.AuthorizationRequest.Builder requestBuilder = new com.nimbusds.oauth2.sdk.AuthorizationRequest.Builder(
                        response.toSuccessResponse().getRequestURI(),
                        new ClientID(oidcIntegrationProperties.getClientId()));
                requestBuilder.endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI());
                return requestBuilder.build();
            } else {
                PushedAuthorizationErrorResponse errorResponse = response.toErrorResponse();
                log.warn("Error response from {}: {}", pushedAuthorizationRequest.getEndpointURI(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                throw new OIDCIntegrationException(errorResponse.getErrorObject().getCode() + ":" + errorResponse.getErrorObject().getDescription());
            }
        } catch (OIDCIntegrationException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public AuthorizationResponse parseAuthorizationResponse(URI authorizationResponseUri) {
        try {
            if (ResponseMode.QUERY_JWT.equals(oidcIntegrationProperties.getResponseMode())) {
                AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(authorizationResponseUri, jarmValidator);
                HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
                oidcProtocolTracerService.traceAuthorizationResponseJWT(request.getSession(), SignedJWT.parse(UriComponentsBuilder.fromUri(authorizationResponseUri).build().getQueryParams().getFirst("response")));
                return authorizationResponse;
            }
            return AuthorizationResponse.parse(authorizationResponseUri);
        } catch (Exception e) {
            log.warn("Failed to parse authorization response {}",authorizationResponseUri, e);
            throw new OIDCIntegrationException("Failed to parse authorization response.");
        }
    }

    public String getJwksEndpoint() {
        return oidcProviderMetadata.getJWKSetURI().toString();
    }


    public List<X509Certificate> getSignatureCertChain(JWT jwt) {
        return getSignatureCertChain(remoteJWKSet.getCachedJWKSet(),  jwt);
    }

    public Map<WarningLevel, List<String>> getSignatureCertChainValidationResults(JWT idToken) {
        try {
            return certChainValidator.validate(getSignatureCertChain(idToken));
        } catch (Exception e) {
           throw new OIDCIntegrationException("Validating Signature Chain Certificate failed");
        }
    }


    public static List<X509Certificate> getSignatureCertChain(@Nullable JWKSet oidcProviderKeys, @Nullable JWT jwt) {
        if (jwt == null || oidcProviderKeys == null) {
            // no-op; need both elements to continue
            return List.of();
        }

        try {
            final JWSHeader jwsHeader = (JWSHeader) jwt.getHeader();
            final String kid = jwsHeader.getKeyID();
            final JWK jwk = oidcProviderKeys.getKeyByKeyId(kid);

            if (jwk == null) {
                log.warn("Unable to validate signing certificate chain, no key found with ID [{}]", kid);
                return List.of();
            }
            return jwk.getParsedX509CertChain();

        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
            return List.of();
        }
    }

    public AccessTokenResponse token(AuthorizationSuccessResponse authorizationResponse, State state, Nonce nonce, CodeVerifier codeVerifier) {
        try {
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationResponse.toSuccessResponse().getAuthorizationCode(), oidcIntegrationProperties.getRedirectUri(), codeVerifier);
            final ClientAuthentication clientAuth = clientAuthentication(oidcIntegrationProperties);
            com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(oidcProviderMetadata.getTokenEndpointURI(), clientAuth, codeGrant);
            com.nimbusds.oauth2.sdk.TokenResponse tokenResponse = process(tokenRequest);
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse accessTokenResponse = tokenResponse.toSuccessResponse();
                if (accessTokenResponse instanceof OIDCTokenResponse) {
                    OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
                    final var idToken = oidcTokenResponse.getOIDCTokens().getIDToken();
                    if (idToken != null) {
                        idTokenValidator.validate(idToken, nonce);
                    }
                }
                return accessTokenResponse;
           } else {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                log.warn("Error response from {}: {}", oidcProviderMetadata.getTokenEndpointURI(), errorResponse.toJSONObject().toJSONString());
                throw new OIDCIntegrationException(errorResponse.getErrorObject().getCode() + ":" + errorResponse.getErrorObject().getDescription());
            }
        } catch (OIDCIntegrationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to retrieve tokens from {}", oidcProviderMetadata.getTokenEndpointURI(), e);
            throw new OIDCIntegrationException("Failed to retrieve tokens.");
        }
    }

    public String userinfo(AccessToken accessToken) {
        try {
            UserInfoRequest userInfoRequest = new UserInfoRequest(oidcProviderMetadata.getUserInfoEndpointURI(), accessToken);
            UserInfoResponse userInfoResponse = process(userInfoRequest);
            if (userInfoResponse.indicatesSuccess()) {
                return userInfoResponse.toSuccessResponse().getUserInfo().toJSONObject().toJSONString();
            } else {
                ErrorResponse errorResponse = userInfoResponse.toErrorResponse();
                log.warn("Error response from {}: {}", oidcProviderMetadata.getUserInfoEndpointURI(), errorResponse.getErrorObject().toJSONObject().toJSONString());
                return errorResponse.getErrorObject().toJSONObject().toJSONString();
            }
        } catch (OIDCIntegrationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to retrieve userinfo from {}", oidcProviderMetadata.getUserInfoEndpointURI(), e);
            throw new OIDCIntegrationException("Failed to retrieve userinfo.");
        }
    }


    public LogoutRequest logoutRequest(JWT idToken) {
        return new LogoutRequest(
                oidcProviderMetadata.getEndSessionEndpointURI(),
                idToken,
                oidcIntegrationProperties.getPostLogoutRedirectUri(),
                new State());
    }

    protected ClientAuthentication clientAuthentication(OIDCIntegrationProperties oidcIntegrationProperties) throws JOSEException {
        ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.parse(oidcIntegrationProperties.getClientAuthMethod());
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC == clientAuthenticationMethod) {
            return new ClientSecretBasic(new ClientID(oidcIntegrationProperties.getClientId()), new Secret(oidcIntegrationProperties.getClientSecret()));
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST == clientAuthenticationMethod) {
            return new ClientSecretPost(new ClientID(oidcIntegrationProperties.getClientId()), new Secret(oidcIntegrationProperties.getClientSecret()));
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_JWT == clientAuthenticationMethod) {
            return new ClientSecretJWT(new ClientID(oidcIntegrationProperties.getClientId()), oidcIntegrationProperties.getIssuer(), JWSAlgorithm.HS256, new Secret(oidcIntegrationProperties.getClientSecret()));
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

    public PushedAuthorizationResponse process(PushedAuthorizationRequest pushedAuthorizationRequest) throws IOException, ParseException {
        HTTPRequest httpRequest = pushedAuthorizationRequest.toHTTPRequest();
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        oidcProtocolTracerService.tracePushedAuthorizationRequest(request.getSession(), httpRequest);
        httpRequest.setConnectTimeout(oidcIntegrationProperties.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(oidcIntegrationProperties.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        oidcProtocolTracerService.tracePushedAuthorizationResponse(request.getSession(), httpResponse);
        return PushedAuthorizationResponse.parse(httpResponse);
    }

    public TokenResponse process(com.nimbusds.oauth2.sdk.TokenRequest tokenRequest) throws IOException, ParseException {
        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        oidcProtocolTracerService.traceTokenRequest(request.getSession(), httpRequest);
        httpRequest.setConnectTimeout(oidcIntegrationProperties.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(oidcIntegrationProperties.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        oidcProtocolTracerService.traceTokenResponse(request.getSession(), httpResponse);
        return OIDCTokenResponseParser.parse(httpResponse);
    }

    public UserInfoResponse process(UserInfoRequest userInfoRequest) throws IOException, ParseException {
        HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        oidcProtocolTracerService.traceUserInfoRequest(request.getSession(), httpRequest);
        httpRequest.setConnectTimeout(oidcIntegrationProperties.getConnectTimeOutMillis());
        httpRequest.setReadTimeout(oidcIntegrationProperties.getReadTimeOutMillis());
        HTTPResponse httpResponse = httpRequest.send();
        oidcProtocolTracerService.traceUserInfoResponse(request.getSession(), httpResponse);
        return UserInfoResponse.parse(httpResponse);
    }

}
