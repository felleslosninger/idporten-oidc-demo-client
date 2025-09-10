package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CertChainValidatorTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CertChainValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CertChainValidator();
    }

    @AfterEach
    void tearDown() {
        validator = null;
    }

    /**
     * Tests the cert chain validator and checks if various date ranges are valid
     *
     * @param daysBefore    certificate issued date - adjusted number of days from today
     * @param daysAfter     certificate expiration date - number of days from today
     * @param throwsError   true when a validation error is expected, otherwise false
     * @param expectedError to be thrown
     */
    @ParameterizedTest(name = "Test #{index}: Given the certificate is valid from {0} days and until {1} days from now, then throwError={2}")
    @CsvSource({
            "-10,90, false, null",
            "-10,-1, true, Signature certificate chain (x5c) for the key id (kid) in your JWT is invalid. Check the JWKS configuration with your OIDC provider. Cause:[Expired at",
            "10,90, true, Signature certificate chain (x5c) for the key id (kid) in your JWT is invalid. Check the JWKS configuration with your OIDC provider. Cause:[Not valid before"
    })
    @DisplayName("given the signing certificate date period is valid, then no errors should be thrown")
    void shouldAcceptSignatureCertificateChainWithinValidityPeriod(int daysBefore, int daysAfter, boolean throwsError, String expectedError) {

        final var notBefore = Date.from(Instant.now().plus(daysBefore, ChronoUnit.DAYS));
        final var notAfter = Date.from(Instant.now().plus(daysAfter, ChronoUnit.DAYS));

        final var jwkRsaKeys = generateJwkRsaKeys("CN=SnakeOil", "CN=SnakeOil", notBefore, notAfter);
        final var jwkSet = new JWKSet(jwkRsaKeys.toPublicJWK());

        final var jwtIssuer = "https://auth.example.com";
        final var jwtSubject = UUID.randomUUID().toString();
        final var signedJWT = generateSignedJWT(jwkRsaKeys, jwtIssuer, jwtSubject);

        final var x5c = OIDCIntegrationService.getSignatureCertChain(jwkSet, signedJWT);

        if (throwsError) {
            final var exception = assertThrows(RuntimeException.class, () -> {
                validator.validate(x5c);
            });

            assertTrue(exception.getMessage().contains(expectedError));

        } else {
            assertDoesNotThrow(() -> {
                validator.validate(x5c);
            });
        }
    }


    private static List<Base64> toBase64(X509Certificate[] chain) {
        final var output = new ArrayList<Base64>(chain.length);
        final var encoder = java.util.Base64.getEncoder();

        try {
            for (X509Certificate cert : chain) {
                String encodedCert = encoder.encodeToString(cert.getEncoded());
                output.add(Base64.from(encodedCert));
            }

        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        return output;
    }

    private KeyPair generateKeyPair() {
        try {
            final var keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new JUnitException("Unable to generate RSA key pair", e);
        }
    }

    private X509Certificate generateCertificate(KeyPair signingKeys, X500Name issuer, X500Name subject, Date notBefore, Date notAfter) {

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        try {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, signingKeys.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signingKeys.getPrivate());

            X509CertificateHolder certHolder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }


    private RSAKey generateJwkRsaKeys(String x5cIssuer, String x5cSubject, Date notBefore, Date notAfter) {
        final var sigKid = UUID.randomUUID().toString();
        final var signingKeys = generateKeyPair();

        X500Name issuer = new X500Name(x5cIssuer);
        X500Name subject = new X500Name(x5cSubject);

        final var certificate = generateCertificate(signingKeys, issuer, subject, notBefore, notAfter);
        final var x5c = new X509Certificate[]{certificate};

        return new RSAKey.Builder((RSAPublicKey) signingKeys.getPublic())
                .privateKey(signingKeys.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(sigKid)
                .issueTime(null)
                .expirationTime(null)
                .x509CertChain(toBase64(x5c))
                .build();
    }

    private SignedJWT generateSignedJWT(RSAKey jwk, String issuer, String subject) {
        try {

            final KeyPair keyPair = jwk.toKeyPair();
            final String keyId = jwk.getKeyID();

            final RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());
            final var claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(issuer)
                    .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                    .build();

            final var signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(keyId).build(), claims);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException ex) {
            throw new RuntimeException("Unable to generate signed JWT, cause: ", ex);
        }
    }
}