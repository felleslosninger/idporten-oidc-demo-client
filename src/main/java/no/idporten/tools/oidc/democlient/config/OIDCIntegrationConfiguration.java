package no.idporten.tools.oidc.democlient.config;

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.extern.slf4j.Slf4j;
import no.idporten.tools.oidc.democlient.config.properties.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.service.LoggingResourceRetriever;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.HashSet;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@Profile("!test")
public class OIDCIntegrationConfiguration {

    @Bean
    public OIDCProviderMetadata oidcProviderMetadata(OIDCIntegrationProperties properties) throws Exception {
        Issuer issuer = new Issuer(properties.getIssuer());
        OIDCProviderMetadata oidcProviderMetadata = OIDCProviderMetadata.resolve(
                issuer,
                properties.getConnectTimeOutMillis(),
                properties.getReadTimeOutMillis());
        log.info("Read OpenID Connect metadata with configuration from issuer {}", issuer);
        return oidcProviderMetadata;
    }

    @Bean
    public RemoteJWKSet remoteJWKSet(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata) throws Exception {
        ResourceRetriever resourceRetriever = new LoggingResourceRetriever(
                properties.getConnectTimeOutMillis(),
                properties.getReadTimeOutMillis());
        DefaultJWKSetCache jwkSetCache = new DefaultJWKSetCache(
                properties.getJwksCacheLifetimeMinutes(),
                properties.getJwksCacheRefreshMinutes(),
                TimeUnit.MINUTES);
        return new RemoteJWKSet(oidcProviderMetadata.getJWKSetURI().toURL(), resourceRetriever, jwkSetCache);
    }

    @Bean
    public IDTokenValidator idTokenValidator(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata, RemoteJWKSet remoteJWKSet) {
        JWSKeySelector<JWKSecurityContext> keySelector = new JWSVerificationKeySelector(
                new HashSet<>(oidcProviderMetadata.getIDTokenJWSAlgs()),
                remoteJWKSet);
        return new IDTokenValidator(
                new Issuer(properties.getIssuer()),
                new ClientID(properties.getClientId()),
                keySelector,
                (JWEKeySelector) null);
    }

    @Bean
    public JARMValidator jarmValidator(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata, RemoteJWKSet remoteJWKSet) {
        JWSKeySelector<JWKSecurityContext> keySelector = new JWSVerificationKeySelector(
                new HashSet<>(oidcProviderMetadata.getIDTokenJWSAlgs()),
                remoteJWKSet);
        return new JARMValidator(
                new Issuer(properties.getIssuer()),
                new ClientID(properties.getClientId()),
                keySelector,
                null);
    }

}
