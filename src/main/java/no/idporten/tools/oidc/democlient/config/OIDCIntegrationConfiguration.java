package no.idporten.tools.oidc.democlient.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.extern.slf4j.Slf4j;
import no.idporten.tools.oidc.democlient.config.properties.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.service.LoggingResourceRetriever;
import no.idporten.tools.oidc.democlient.service.OIDCProviderMetadataSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.HashSet;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@Profile("!test")
public class OIDCIntegrationConfiguration {

    // Metadata read once at startup; endpoints, JWKS URI and signing algorithms are taken from this snapshot.
    @Bean
    public OIDCProviderMetadata oidcProviderMetadata(OIDCIntegrationProperties properties) throws Exception {
        OIDCProviderMetadata oidcProviderMetadata = resolveMetadata(properties);
        log.info("Read OpenID Connect metadata with configuration from issuer {}", properties.getIssuer());
        return oidcProviderMetadata;
    }

    // Re-reads the discovery document on every call, falling back to the startup snapshot when the provider is unreachable.
    @Bean
    public OIDCProviderMetadataSupplier oidcProviderMetadataSupplier(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata) {
        return () -> {
            try {
                return resolveMetadata(properties);
            } catch (Exception e) {
                log.warn("Failed to read OpenID Connect metadata from issuer {}, using the metadata read at startup", properties.getIssuer(), e);
                return oidcProviderMetadata;
            }
        };
    }

    private static OIDCProviderMetadata resolveMetadata(OIDCIntegrationProperties properties) throws Exception {
        return OIDCProviderMetadata.resolve(
                new Issuer(properties.getIssuer()),
                properties.getConnectTimeOutMillis(),
                properties.getReadTimeOutMillis());
    }

    // The JWKS is cached for jwks-cache-refresh-minutes and re-read on expiry or on an unknown kid; if the provider is
    // unreachable the last good copy is kept for jwks-cache-lifetime-minutes.
    @Bean
    public JWKSource<SecurityContext> jwkSource(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata) throws Exception {
        ResourceRetriever resourceRetriever = new LoggingResourceRetriever(
                properties.getConnectTimeOutMillis(),
                properties.getReadTimeOutMillis());
        return JWKSourceBuilder.<SecurityContext>create(oidcProviderMetadata.getJWKSetURI().toURL(), resourceRetriever)
                .cache(TimeUnit.MINUTES.toMillis(properties.getJwksCacheRefreshMinutes()), JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
                .outageTolerant(TimeUnit.MINUTES.toMillis(properties.getJwksCacheLifetimeMinutes()))
                .build();
    }

    @Bean
    public IDTokenValidator idTokenValidator(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata, JWKSource<SecurityContext> jwkSource) {
        return new IDTokenValidator(
                new Issuer(properties.getIssuer()),
                new ClientID(properties.getClientId()),
                keySelector(oidcProviderMetadata, jwkSource),
                (JWEKeySelector<SecurityContext>) null);
    }

    @Bean
    public JARMValidator jarmValidator(OIDCIntegrationProperties properties, OIDCProviderMetadata oidcProviderMetadata, JWKSource<SecurityContext> jwkSource) {
        return new JARMValidator(
                new Issuer(properties.getIssuer()),
                new ClientID(properties.getClientId()),
                keySelector(oidcProviderMetadata, jwkSource),
                null);
    }

    private static JWSKeySelector<SecurityContext> keySelector(OIDCProviderMetadata oidcProviderMetadata, JWKSource<SecurityContext> jwkSource) {
        return new JWSVerificationKeySelector<>(new HashSet<>(oidcProviderMetadata.getIDTokenJWSAlgs()), jwkSource);
    }

}
