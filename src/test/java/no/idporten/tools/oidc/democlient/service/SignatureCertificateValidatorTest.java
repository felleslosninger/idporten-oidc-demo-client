package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.jwk.JWKSet;
import no.idporten.tools.oidc.democlient.TestDataUtils;
import no.idporten.tools.oidc.democlient.util.WarningLevel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static no.idporten.tools.oidc.democlient.service.SignatureCertificateValidator.getSignatureCertChain;
import static org.junit.jupiter.api.Assertions.*;

class SignatureCertificateValidatorTest {

    static {
        // synthetic certificate chain generation
        Security.addProvider(new BouncyCastleProvider());
    }

    private SignatureCertificateValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SignatureCertificateValidator();
    }

    @AfterEach
    void tearDown() {
        validator = null;
    }

    /**
     * Tests the cert chain validator and checks if various date ranges are valid
     *
     * @param daysBefore      certificate issued date - adjusted number of days from today
     * @param daysAfter       certificate expiration date - number of days from today
     * @param isErrorExpected true when a validation error is expected, otherwise false
     * @param errorLevel      severity of the validation error
     */
    @ParameterizedTest(name = "Test #{index}: The certificate has validity from {0} days and until {1} days from now, result should valid={2} with \"{3}: {4}\"")
    @CsvSource({
            "-10, 90, false, null, null",
            "-10, -1, true, ERROR, Certificate expired", // Expired 1 day ago
            "10, 90, true, WARNING, Certificate not valid", // Issue date 10 days ahead
            "-10, 3, true, WARNING, Certificate expires soon" // Expires 3 days ahead
    })
    @DisplayName("Given a certificate is provided, then the validator should check dates and return a warning or an error if invalid")
    void givenDifferentIssuedAndExpiryDatesTheValidatorShouldReturnSensibleLevelsAndMessages(int daysBefore, int daysAfter, boolean isErrorExpected, String errorLevel, String expectedMessage) {
        // given
        final var notBefore = Date.from(Instant.now().plus(daysBefore, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(daysAfter, ChronoUnit.DAYS));

        final var jwkRsaKeys = TestDataUtils.generateJwkRsaKeys("CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys, jwtIssuer, jwtSubject);

        final var x5c = getSignatureCertChain(jwkSet, signedJWT);

        // when
        final var actual = validator.validate(x5c);

        // then
        if (isErrorExpected) {
            assertAll(
                    () -> assertEquals(1, actual.size()),
                    () -> assertNotNull(actual.getFirst().level()),
                    () -> assertNotNull(actual.getFirst().message()),
                    () -> assertEquals(WarningLevel.valueOf(errorLevel), actual.getFirst().level()),
                    () -> assertTrue(actual.getFirst().message().contains(expectedMessage))
            );

        } else {
            assertTrue(actual.isEmpty());
        }
    }

    @Test
    @Disabled
    @DisplayName(value = "Given ther are multiple certificates in chain, the validator should only check root certificate")
    void givenThereAreMultipleCertificatesInChainThenTheValidatorShouldCheckRootCertificate() {
        // TODO: Add test case scenario for real-life x5c with root cert + multiple chained certs

        // given
        final var notBefore = Date.from(Instant.now().plus(-180, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(180, ChronoUnit.DAYS));

        //TODO
        final var jwkRsaKeys = TestDataUtils.generateJwkRsaKeys("CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys, jwtIssuer, jwtSubject);

        final var x5c = getSignatureCertChain(jwkSet, signedJWT);

        // when
        final var actual = validator.validate(x5c);

        // then
        //TODO
    }


    @Test
    @DisplayName(value = "Given no certificate chain is given, then the validator should issue a warning")
    void shouldHandleMissingCertificateChain() {
        // given
        final List<X509Certificate> x5c = null;

        // when
        final var actual = validator.validate(null);

        // then
        assertAll(
                () -> assertFalse(actual.isEmpty()),
                () -> assertEquals(1, actual.size()),
                () -> assertNotNull(actual.getFirst().level()),
                () -> assertNotNull(actual.getFirst().message()),
                () -> assertEquals(WarningLevel.WARNING, actual.getFirst().level()),
                () -> assertEquals("Certificate chain was not found", actual.getFirst().message())
        );
    }

    @Test
    @DisplayName(value = "Given an empty certificate chain is given, then the validator should issue a warning")
    void shouldHandleEmptyCertificateChain() {
        // given
        final List<X509Certificate> x5c = null;

        // when
        final var actual = validator.validate(x5c);

        // then
        assertAll(
                () -> assertFalse(actual.isEmpty()),
                () -> assertEquals(1, actual.size()),
                () -> assertNotNull(actual.getFirst().level()),
                () -> assertNotNull(actual.getFirst().message()),
                () -> assertEquals(WarningLevel.WARNING, actual.getFirst().level()),
                () -> assertEquals("Certificate chain was not found", actual.getFirst().message())
        );
    }

    @Test
    @DisplayName(value = "Given null parameters, then signature certificate chain retrieval should not fail")
    void shouldHandleNullCertificateChain() {

        assertDoesNotThrow(() -> {
            final var x5c = getSignatureCertChain(null, null);
            assertAll(
                    () -> assertNotNull(x5c),
                    () -> assertTrue(x5c.isEmpty())
            );
        });
    }

    @Test
    @DisplayName(value = "Given a non-related kid on the JWT, then retrieval attempt of cert chain should not crash but give an empty list")
    void shouldHandleKeyNotFoundInKeySet() {
        final var notBefore = Date.from(Instant.now().plus(-365, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));

        final var jwkRsaKeys = TestDataUtils.generateJwkRsaKeys("CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedButMisleadingJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys, jwtIssuer, jwtSubject, "NøtteNøtteNøkkel?");
        assertDoesNotThrow(() -> {
            final var x5c = getSignatureCertChain(jwkSet, signedButMisleadingJWT);
            assertAll(
                    () -> assertNotNull(x5c),
                    () -> assertTrue(x5c.isEmpty())
            );
        });
    }

    @Test
    @DisplayName(value = "Given a valid kid on the JWT, then retrieval attempt of cert chain should succeed")
    void shouldHandleValidKeyAndReturnCertificateChain() {
        // given
        final var notBefore = Date.from(Instant.now().plus(-365, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));

        final var jwkRsaKeys = TestDataUtils.generateJwkRsaKeys("CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();

        // when
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys, jwtIssuer, jwtSubject);

        // then
        assertDoesNotThrow(() -> {
            final var x5c = getSignatureCertChain(jwkSet, signedJWT);
            assertAll(
                    () -> assertNotNull(x5c),
                    () -> assertEquals(1, x5c.size())
            );
        });
    }
}