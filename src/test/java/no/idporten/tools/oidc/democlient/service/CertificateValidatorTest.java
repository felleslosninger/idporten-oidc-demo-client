package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.JUnitException;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class CertificateValidatorTest {

    private CertificateValidator instance;

    @BeforeEach
    void setUp() {
        instance = new CertificateValidator();
    }

    @AfterEach
    void tearDown() {
        instance = null;
    }

    @Test
    @DisplayName("given the signing certificate date period is valid, then no errors should be thrown")
    void shouldAcceptSignatureCertificateChainWithinValidiityPeriod() {
        final var kid = UUID.randomUUID().toString();

        final var yesterday = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        final var tomorrow = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));
        final var keyPair = generatePrivatePublicKeys(kid, yesterday, tomorrow);

        final var privateKey = keyPair.getLeft();
        final var publicKey = keyPair.getRight();

        // TODO find key chain type
        final var jwk = toJWK(privateKey,publicKey, List.of());

        final var authServerJWKS = new JWKSet(jwk);
        final var idToken = getSampleJWT(privateKey, publicKey, "Testulf Testen", "https://example.org");

        assertDoesNotThrow(() -> {
           instance.validate(authServerJWKS, idToken);
        });

    }

    private static JWK toJWK(RSAKey privateKey, RSAKey publicKey, List<Base64> x509Chain) {
        try {
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey.toPrivateKey())
                    .keyID(publicKey.getKeyID())
                    .x509CertChain(x509Chain)
                    .build();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private Pair<RSAKey, RSAKey> generatePrivatePublicKeys(String keyId, Date iat, Date exp) {
        try {
            final RSAKey privateKey = new RSAKeyGenerator(2048)
                    .keyID(keyId)
                    .issueTime(iat)
                    .expirationTime(exp)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
            final RSAKey publicKey = privateKey.toPublicJWK();
            return Pair.of(privateKey, publicKey);

        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }


    }

    private SignedJWT getSampleJWT(RSAKey privateKey, RSAKey publicKey, String subject, String issuer) {
        try {
            final RSASSASigner signer = new RSASSASigner(privateKey);
            final var claims = new JWTClaimsSet.Builder()
                    .subject("Testulf Testen")
                    .issuer("https://example.com")
                    .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                    .build();

            final var signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(publicKey.getKeyID()).build(), claims);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

    }

    private JWKSet getSampleJWKSet() {
        final var input = "";
        final JWKSet parsed;
        try {
            parsed = JWKSet.parse(input);
        } catch (ParseException e) {
            throw new JUnitException("Failed to parse JWKSet", e);
        }
        return parsed;
    }
}