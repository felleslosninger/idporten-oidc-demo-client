package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When validating the acr claim of an ID token")
class AcrValidatorTest {

    private static final List<String> PUBLISHED = List.of("idporten-loa-substantial", "idporten-loa-high", "eidas-loa-substantial", "eidas-loa-high");

    private static OIDCProviderMetadata metadata(List<String> acrValuesSupported) {
        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                new Issuer("https://junit.idporten.no"),
                List.of(SubjectType.PUBLIC),
                URI.create("https://junit.idporten.no/jwks"));
        if (acrValuesSupported != null) {
            metadata.setACRs(acrValuesSupported.stream().map(ACR::new).toList());
        }
        return metadata;
    }

    private static AcrValidator validator(List<String> acrValuesSupported) {
        OIDCProviderMetadata metadata = metadata(acrValuesSupported);
        return new AcrValidator(() -> metadata);
    }

    @Nested
    @DisplayName("and the provider publishes acr_values_supported")
    class PublishedTests {

        private final AcrValidator validator = validator(PUBLISHED);

        @Test
        @DisplayName("then the supported values are the published ones, in order")
        void testSupportedAcrValues() {
            assertEquals(PUBLISHED, validator.supportedAcrValues());
        }

        @ParameterizedTest(name = "acr {0} is accepted")
        @ValueSource(strings = {"idporten-loa-substantial", "idporten-loa-high", "eidas-loa-high"})
        @DisplayName("then a published value is accepted")
        void testAccepted(String acr) {
            assertDoesNotThrow(() -> validator.validate(acr));
        }

        @Test
        @DisplayName("then an unpublished value is rejected")
        void testRejected() {
            OIDCIntegrationException e = assertThrows(OIDCIntegrationException.class, () -> validator.validate("Level4"));
            assertEquals("Level4: is not one of acr_values_supported: " + String.join(", ", PUBLISHED), e.getMessage());
        }

        @Test
        @DisplayName("then a missing acr claim is rejected")
        void testMissing() {
            assertThrows(OIDCIntegrationException.class, () -> validator.validate(null));
        }
    }

    @Nested
    @DisplayName("and the provider changes acr_values_supported after startup")
    class ChangedAfterStartupTests {

        @Test
        @DisplayName("then the current values are used on every call")
        void testReadsCurrentMetadataOnEveryCall() {
            Iterator<OIDCProviderMetadata> published = List.of(metadata(PUBLISHED), metadata(List.of("idporten-loa-substantial-limited"))).iterator();
            AcrValidator validator = new AcrValidator(published::next);
            assertAll(
                    () -> assertThrows(OIDCIntegrationException.class, () -> validator.validate("idporten-loa-substantial-limited")),
                    () -> assertDoesNotThrow(() -> validator.validate("idporten-loa-substantial-limited"))
            );
        }
    }

    @Nested
    @DisplayName("and the provider publishes no acr_values_supported")
    class UnpublishedTests {

        private final AcrValidator validator = validator(null);

        @Test
        @DisplayName("then there are no supported values and nothing is rejected")
        void testNothingToValidateAgainst() {
            assertAll(
                    () -> assertEquals(List.of(), validator.supportedAcrValues()),
                    () -> assertDoesNotThrow(() -> validator.validate("anything")),
                    () -> assertDoesNotThrow(() -> validator.validate(null))
            );
        }
    }

}
