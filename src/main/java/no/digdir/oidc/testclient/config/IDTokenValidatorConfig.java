package no.digdir.oidc.testclient.config;

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import no.digdir.oidc.testclient.service.LoggingResourceRetriever;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Configuration
public class IDTokenValidatorConfig {

    @Bean
    public IDTokenValidator idTokenValidator(IDPortenIntegrationConfiguration config, RemoteJWKSet remoteJWKSet) {
        JWSKeySelector<JWKSecurityContext> keySelector = new JWSVerificationKeySelector(config.getIdTokenConfig().getJwsAlgorithms(), remoteJWKSet);
        return new IDTokenValidator(new Issuer(config.getIssuer()), new ClientID(config.getClientId()), keySelector, (JWEKeySelector) null);
    }

    @Bean
    public RemoteJWKSet remoteJWKSet(IDPortenIntegrationConfiguration config) throws IOException {
        ResourceRetriever resourceRetriever = new LoggingResourceRetriever(config.getConnectTimeOutMillis(), config.getReadTimeOutMillis());
        DefaultJWKSetCache jwkSetCache = new DefaultJWKSetCache(config.getJwksCacheLifetimeMinutes(), config.getJwksCacheRefreshMinutes(), TimeUnit.MINUTES);
        return new RemoteJWKSet(config.getJwksEndpoint().toURL(), resourceRetriever, jwkSetCache);
    }

}
