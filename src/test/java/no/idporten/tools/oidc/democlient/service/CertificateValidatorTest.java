package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class CertificateValidatorTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CertificateValidator instance;

    @BeforeEach
    void setUp() {
        instance = new CertificateValidator();
    }

    @AfterEach
    void tearDown() {
        instance = null;
    }



    /*
    private List<java.util.Base64> getBase64ChainFromX509(List<String> x5cString) {
        final var result = new ArrayList<java.util.Base64>(x5cString.size());
        final var expiredX5C = List.of("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");
        try {
            final var presentedChain = new ArrayList<X509Certificate>(expiredX5C.size());
            final var factory = CertificateFactory.getInstance("X.509");

            final java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
            for (final var b64 : expiredX5C) {
               result.add(java.util.Base64.of)
            }
        }
    }
     */


    @Test
    @SneakyThrows
    @DisplayName("given the signing certificate date period is valid, then no errors should be thrown")
    void shouldAcceptSignatureCertificateChainWithinValidiityPeriod() {

        final var sigKid = UUID.randomUUID().toString();
        final var yesterday = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        final var tomorrow = Date.from(Instant.now().plus(15, ChronoUnit.DAYS));

        final var keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name("CN=test");
        X500Name subject = new X500Name("CN=test");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = yesterday;
        Date notAfter = tomorrow;


        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);
        X509Certificate[] chain = new X509Certificate[] {certificate};


        final var rootKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .keyID(sigKid)
                .issueTime(yesterday)
                .expirationTime(tomorrow)
                .x509CertChain(toBase64(chain))
                .build();

        final var publicRootJWK = rootKey.toPublicJWK();
        final var publicRootJWKset = new JWKSet(publicRootJWK);

        final var signedJWT =  generateSignedJWT(rootKey.toKeyPair(), rootKey.getKeyID(), issuer.toString(), subject.toString());


        assertDoesNotThrow(() -> {
            instance.validate(publicRootJWKset, signedJWT);
        });

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

    private SignedJWT generateSignedJWT(KeyPair signingKey, String kid, String sub, String iss) {
        try {
            final RSASSASigner signer = new RSASSASigner(signingKey.getPrivate());
            final var claims = new JWTClaimsSet.Builder()
                    .subject(sub)
                    .issuer(iss)
                    .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                    .build();

            final var signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(kid).build(), claims);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

    }
}