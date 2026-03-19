package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import no.idporten.tools.oidc.democlient.TestDataUtils;
import no.idporten.tools.oidc.democlient.config.properties.FeatureSwitchProperties;
import no.idporten.tools.oidc.democlient.config.properties.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.crypto.KeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

@DisplayName("OIDCIntegrationService")
class OIDCIntegrationServiceTest {

    private OIDCIntegrationService service;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() {
        service = new OIDCIntegrationService(
                mock(OIDCIntegrationProperties.class),
                Optional.empty(),
                mock(IDTokenValidator.class),
                mock(JARMValidator.class),
                mock(OIDCProviderMetadata.class),
                mock(ProtocolTracerService.class),
                mock(FeatureSwitchProperties.class),
                mock(SignatureCertificateValidator.class),
                mock(RemoteJWKSet.class)
        );
        keyPair = TestDataUtils.generateRSAKeyPair();
    }

    private BearerAccessToken signedAccessToken(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);
        jwt.sign(new RSASSASigner(keyPair.getPrivate()));
        return new BearerAccessToken(jwt.serialize());
    }

    @Nested
    @DisplayName("When validating amr claim in access token")
    class AmrValidationTests {

        @Test
        @DisplayName("then validation passes when amr claim is present")
        void testAmrPresentPasses() throws Exception {
            BearerAccessToken accessToken = signedAccessToken(new JWTClaimsSet.Builder()
                    .claim("amr", List.of("BankID"))
                    .build());
            assertDoesNotThrow(() -> service.validateAccessTokenAmr(accessToken));
        }

        @Test
        @DisplayName("then OIDCIntegrationException is thrown when amr claim is missing")
        void testMissingAmrFails() throws Exception {
            BearerAccessToken accessToken = signedAccessToken(new JWTClaimsSet.Builder().build());
            assertThrows(OIDCIntegrationException.class, () -> service.validateAccessTokenAmr(accessToken));
        }

        @Test
        @DisplayName("then OIDCIntegrationException is thrown when amr claim is empty")
        void testEmptyAmrFails() throws Exception {
            BearerAccessToken accessToken = signedAccessToken(new JWTClaimsSet.Builder()
                    .claim("amr", List.of())
                    .build());
            assertThrows(OIDCIntegrationException.class, () -> service.validateAccessTokenAmr(accessToken));
        }

        @Test
        @DisplayName("then validation is skipped without error for opaque access tokens")
        void testOpaqueTokenSkipped() {
            BearerAccessToken opaqueToken = new BearerAccessToken("opaque-token-value");
            assertDoesNotThrow(() -> service.validateAccessTokenAmr(opaqueToken));
        }

    }

}
