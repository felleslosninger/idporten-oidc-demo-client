package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import no.idporten.tools.oidc.democlient.TestDataUtils;
import no.idporten.tools.oidc.democlient.config.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.util.WarningLevel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static no.idporten.tools.oidc.democlient.TestDataUtils.*;
import static no.idporten.tools.oidc.democlient.service.SignatureCertificateValidator.getSignatureCertChain;
import static org.junit.jupiter.api.Assertions.*;

class SignatureCertificateValidatorTest {

    static {
        // required to generate certificates
        Security.addProvider(new BouncyCastleProvider());
    }

    private SignatureCertificateValidator validator;

    private OIDCIntegrationProperties properties;

    @BeforeEach
    void setUp() {
        properties = new OIDCIntegrationProperties();
        validator = new SignatureCertificateValidator(properties);
    }

    @AfterEach
    void tearDown() {
        validator = null;
        properties = null;
    }

    /**
     * Tests the cert chain validator and checks if various date ranges are valid
     *
     * @param expiryWarningDays number of days to lookahead and generate a warning if the certificate expires
     * @param daysBefore        certificate issued date - adjusted number of days from today
     * @param daysAfter         certificate expiration date - number of days from today
     * @param isErrorExpected   true when a validation error is expected, otherwise false
     * @param errorLevel        severity of the validation error
     */
    @ParameterizedTest(name = "Test #{index}: The certificate has validity from {0} days and until {1} days from now, result should valid={2} with \"{3}: {4}\"")
    @CsvSource({
            "7, -10, 90, false, null, null",
            "7, -10, -1, true, ERROR, Certificate expired", // Expired 1 day ago
            "7,  10, 90, true, WARNING, Certificate not valid", // Issue date 10 days ahead
            "7, -10,  3, true, WARNING, Certificate expires soon" // Expires 3 days ahead
    })
    @DisplayName("Given a certificate is provided, then the validator should check dates and return a warning or an error if invalid")
    void givenDifferentIssuedAndExpiryDatesTheValidatorShouldReturnSensibleLevelsAndMessages(int expiryWarningDays, int daysBefore, int daysAfter, boolean isErrorExpected, String errorLevel, String expectedMessage) throws JOSEException {
        // given
        final var notBefore = Date.from(Instant.now().plus(daysBefore, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(daysAfter, ChronoUnit.DAYS));

        final var signatureKeys = generateRSAKeyPair();
        final var signatureCertificate = generateCertificate(signatureKeys.getPublic(), signatureKeys.getPrivate(), "CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);

        final var jwkRsaKeys = TestDataUtils.generateRsaSignatureJWK(signatureKeys, "A", new X509Certificate[]{signatureCertificate});
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys.toPrivateKey(), jwtIssuer, jwtSubject, jwkRsaKeys.getKeyID());

        final var x5c = getSignatureCertChain(jwkSet, signedJWT).getFirst();

        // when
        properties.setJwksExpiryWarningDays(expiryWarningDays);
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
    @DisplayName(value = "Given there are multiple certificates in chain, the validator should only check the first certificate")
    void givenThereAreMultipleCertificatesInChainThenTheValidatorShouldCheckRootCertificate() throws JOSEException {

        // given we have a valid key set
        final var halfYear = Duration.ofDays(180);
        final var validStart = Date.from(Instant.now().minus(halfYear));
        final var validEnd = Date.from(Instant.now().plus(halfYear));
        final var caKeys = generateRSAKeyPair();
        final var intermediateKeys = generateRSAKeyPair();
        final var signatureKeys = generateRSAKeyPair();

        final var rootCertificate = generateCertificate(caKeys.getPublic(), caKeys.getPrivate(), "CN=SnakeOil CA", "CN=SnakeOil CA", validStart, validEnd);
        final var intermediateCert = generateCertificate(intermediateKeys.getPublic(), caKeys.getPrivate(), "CN=SnakeOil CA", "CN=SnakeOil Intermediate", validStart, validEnd);
        final var signatureCertificate = generateCertificate(signatureKeys.getPublic(), intermediateKeys.getPrivate(), "CN=SnakeOil Intermediate", "CN=SnakeOil Signature", validStart, validEnd);
        final var chain = new X509Certificate[]{signatureCertificate, intermediateCert, rootCertificate};

        final var jwkRsaKey = generateRsaSignatureJWK(signatureKeys, "A", chain);
        final var jwkSet = new JWKSet(jwkRsaKey.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKey.toPrivateKey(), jwtIssuer, jwtSubject, jwkRsaKey.getKeyID());

        final var x5c = getSignatureCertChain(jwkSet, signedJWT).getFirst();

        // when
        final var actual = validator.validate(x5c);

        // then
        assertAll(
                () -> assertEquals(0, actual.size())
        );
    }

    @Test
    @DisplayName(value = "Given the certificate soon expires, then the warning message should contain the correct date")
    void warningShouldIncludeCorrectExpiryDate() throws JOSEException {

        final var halfYear = 180;
        final var warningPeriod = 270;
        final var notBefore = Date.from(Instant.now().minus(halfYear, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(halfYear, ChronoUnit.DAYS));

        final var keyPair = TestDataUtils.generateRSAKeyPair();
        final var certificate = TestDataUtils.generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkRsaKeys = TestDataUtils.generateRsaSignatureJWK(keyPair, "A", new X509Certificate[]{certificate});
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();

        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys.toPrivateKey(), jwtIssuer, jwtSubject, jwkRsaKeys.getKeyID());
        final var x5c = getSignatureCertChain(jwkSet, signedJWT).getFirst();


        assertDoesNotThrow(() -> {
            properties.setJwksExpiryWarningDays(warningPeriod);
            final var result = validator.validate(x5c);

            final var formattedExpectedDate = notAfter.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate().format(DateTimeFormatter.ISO_DATE);

            assertAll(
                    () -> assertNotNull(result),
                    () -> assertEquals(1, result.size()),
                    () -> assertEquals(WarningLevel.WARNING, result.getFirst().level()),
                    () -> assertEquals("Certificate expires soon [" + formattedExpectedDate + "]", result.getFirst().message())
            );
        });

    }


    @Test
    @DisplayName(value = "Given the certificate has expired, then the error message should contain the correct date")
    void errorShouldIncludeCorrectExpiryDate() throws JOSEException {

        final var defaultWarningPeriod = 30;
        final var notBefore = Date.from(Instant.now().minus(360, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().minus(180, ChronoUnit.DAYS));

        final var keyPair = TestDataUtils.generateRSAKeyPair();
        final var certificate = TestDataUtils.generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkRsaKeys = TestDataUtils.generateRsaSignatureJWK(keyPair, "A", new X509Certificate[]{certificate});
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();

        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys.toPrivateKey(), jwtIssuer, jwtSubject, jwkRsaKeys.getKeyID());
        final var x5c = getSignatureCertChain(jwkSet, signedJWT).getFirst();


        assertDoesNotThrow(() -> {
            properties.setJwksExpiryWarningDays(defaultWarningPeriod);
            final var result = validator.validate(x5c);

            final var formattedExpectedDate = notAfter.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate().format(DateTimeFormatter.ISO_DATE);

            assertAll(
                    () -> assertNotNull(result),
                    () -> assertEquals(1, result.size()),
                    () -> assertEquals(WarningLevel.ERROR, result.getFirst().level()),
                    () -> assertEquals("Certificate expired [" + formattedExpectedDate + "]", result.getFirst().message())
            );
        });

    }


    @Test
    @DisplayName(value = "Given no certificate chain is given, then the validator should issue a warning")
    void shouldHandleMissingCertificateChain() {
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
        X509Certificate x5c = null;

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
    void shouldHandleKeyNotFoundInKeySet() throws JOSEException {
        final var notBefore = Date.from(Instant.now().plus(-365, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));

        final var signatureKeys = TestDataUtils.generateRSAKeyPair();
        final var signatureCertificate = TestDataUtils.generateCertificate(signatureKeys.getPublic(), signatureKeys.getPrivate(), "CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);

        final var jwkRsaKeys = TestDataUtils.generateRsaSignatureJWK(signatureKeys, UUID.randomUUID().toString(), new X509Certificate[]{signatureCertificate});
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedButMisleadingJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys.toPrivateKey(), jwtIssuer, jwtSubject, "loremIpsumKey");
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
    void shouldHandleValidKeyAndReturnCertificateChain() throws JOSEException {
        // given
        final var notBefore = Date.from(Instant.now().plus(-365, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));

        final var keyPair = TestDataUtils.generateRSAKeyPair();
        final var certificate = TestDataUtils.generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), "CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkRsaKeys = TestDataUtils.generateRsaSignatureJWK(keyPair, "A", new X509Certificate[]{certificate});
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();

        // when
        final var signedJWT = TestDataUtils.generateSignedJWT(jwkRsaKeys.toPrivateKey(), jwtIssuer, jwtSubject, jwkRsaKeys.getKeyID());

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