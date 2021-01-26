package no.digdir.oidc.testclient;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.oidc.testclient.config.IDPortenIntegrationConfiguration;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindException;
import org.springframework.validation.Validator;

@Slf4j
@RequiredArgsConstructor
@Component
@Profile("!test")
public class IDPortenTestClientApplicationListener implements ApplicationListener<ApplicationReadyEvent> {

    private final IDPortenIntegrationConfiguration eidIntegrationConfiguration;
    private final RemoteJWKSet remoteJWKSet;
    private final Validator validator;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        try {
            if (eidIntegrationConfiguration.getFeatures().isReadMetadataOnStartup()) {
                loadOpenIDConnectMetadata();
                loadJwks();
                validateConfig();
            }
        } catch (Exception e) {
            log.error("Failed to process metadata from eID OpenID Connect provider", e);
            event.getApplicationContext().close();
        }
    }

    protected void loadJwks() throws Exception {
        remoteJWKSet.get(new JWKSelector(
                new JWKMatcher.Builder()
                        .algorithm(eidIntegrationConfiguration.getIdTokenConfig().getJwsAlgorithms().iterator().next())
                        .build()),
                null);
        log.info("Cached JWKS from {}", remoteJWKSet.getJWKSetURL());
    }

    protected void loadOpenIDConnectMetadata() {
        Issuer issuer = new Issuer(eidIntegrationConfiguration.getIssuer());
        try {
            OIDCProviderMetadata oidcProviderMetadata = OIDCProviderMetadata.resolve(issuer, eidIntegrationConfiguration.getConnectTimeOutMillis(), eidIntegrationConfiguration.getReadTimeOutMillis());
            eidIntegrationConfiguration.setAuthorizationEndpoint(oidcProviderMetadata.getAuthorizationEndpointURI());
            eidIntegrationConfiguration.setTokenEndpoint(oidcProviderMetadata.getTokenEndpointURI());
            eidIntegrationConfiguration.setJwksEndpoint(oidcProviderMetadata.getJWKSetURI());
            log.info("Replaced OpenID Connect metadata with configuration from issuer {}", issuer);
        } catch (Exception e) {
            log.error("Failed to read OpenID Connect metadata for issuer {} - fallback to default from config", issuer, e);
        }
    }

    protected void validateConfig() throws Exception {
        BindException e = new BindException(this, "eid-integration.eid-provider");
        validator.validate(eidIntegrationConfiguration, e);
        if (e.hasErrors()) {
            throw e;
        }
    }

}
