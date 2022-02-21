package no.idporten.tools.oidc.democlient.config;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Slf4j
@Configuration
@Profile("test")
public class OIDCIntegrationTestConfiguration {

    @Bean
    public OIDCProviderMetadata junitOidcProviderMetadata(OIDCIntegrationProperties properties) throws Exception {
        OIDCProviderMetadata oidcProviderMetadata = OIDCProviderMetadata.parse("{\n" +
                "\"issuer\": \"http://junit.idporten.no/testid/\",\n" +
                "\"pushed_authorization_request_endpoint\": \"http://junit.idporten.no/testid/par\",\n" +
                "\"authorization_endpoint\": \"http://junit.idporten.no/testid/authorize\",\n" +
                "\"token_endpoint\": \"http://junit.idporten.no/testid/token\",\n" +
                "\"jwks_uri\": \"http://junit.idporten.no/testid/jwks\",\n" +
                "\"userinfo_endpoint\": \"http://junit.idporten.no/testid/userinfo\",\n" +
                "\"end_session_endpoint\": \"http://junit.idporten.no/testid/endsession\",\n" +
                "\"scopes_supported\": [\n" +
                "\"openid\"\n" +
                "],\n" +
                "\"response_types_supported\": [\n" +
                "\"code\"\n" +
                "],\n" +
                "\"response_modes_supported\": [\n" +
                "\"query\"\n" +
                "],\n" +
                "\"grant_types_supported\": [\n" +
                "\"authorization_code\"\n" +
                "],\n" +
                "\"acr_values_supported\": [\n" +
                "\"Level3\",\n" +
                "\"Level4\"\n" +
                "],\n" +
                "\"subject_types_supported\": [\n" +
                "\"public\"\n" +
                "],\n" +
                "\"id_token_signing_alg_values_supported\": [\n" +
                "\"RS256\"\n" +
                "],\n" +
                "\"token_endpoint_auth_methods_supported\": [\n" +
                "\"client_secret_basic\",\n" +
                "\"client_secret_post\"\n" +
                "],\n" +
                "\"ui_locales_supported\": [\n" +
                "\"nb\"\n" +
                "]\n" +
                "}");
        return oidcProviderMetadata;
    }

    @MockBean
    public RemoteJWKSet remoteJWKSet;

    @MockBean
    public IDTokenValidator idTokenValidator;

}
