package no.idporten.tools.oidc.democlient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
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
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

/**
 * Utilities for test data.
 */
public class TestDataUtils {

    public static String testUserPersonIdentifier() {
        return "11223312345";
    }

    public static JWTClaimsSet idTokenClaimsSet(String personIDentifier) {
        try {
            return JWTClaimsSet.parse(String.format("{\n" +
                    "  \"sub\" : \"sub-11223312345\",\n" +
                    "  \"aud\" : \"idporten-oidc-demo-client\",\n" +
                    "  \"acr\" : \"Level4\",\n" +
                    "  \"amr\" : [ \"testid2\" ],\n" +
                    "  \"auth_time\" : 1612351397,\n" +
                    "  \"iss\" : \"https://c2id-demo.westeurope.cloudapp.azure.com\",\n" +
                    "  \"pid\" : \"11223312345\",\n" +
                    "  \"exp\" : 1612351517,\n" +
                    "  \"locale\" : \"nb\",\n" +
                    "  \"iat\" : 1612351397,\n" +
                    "  \"nonce\" : \"QrxBHIQb-_iSwg98FgJgn9X1j3USkFmEvOnDaLY79HA\",\n" +
                    "  \"sid\" : \"s322f2-CbxLN8Hm-kQew8f0w8HwE7l1-HSCKmrGYGN4\"\n" +
                    "}", personIDentifier));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static List<Base64> toBase64(X509Certificate[] chain) {
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

    public static KeyPair generateRSAKeyPair() {
        try {
            final var keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new JUnitException("Unable to generate RSA key pair", e);
        }
    }

    public static X509Certificate generateCertificate(KeyPair signingKeys, X500Name issuer, X500Name subject, Date notBefore, Date notAfter) {

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


    public static RSAKey generateJwkRsaKeys(String x5cIssuer, String x5cSubject, Date notBefore, Date notAfter) {
        final var sigKid = UUID.randomUUID().toString();
        final var signingKeys = generateRSAKeyPair();

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

    public static SignedJWT generateSignedJWT(RSAKey jwk, String issuer, String subject) {
        return generateSignedJWT(jwk, issuer, subject, jwk.getKeyID());
    }

    public static SignedJWT generateSignedJWT(RSAKey jwk, String issuer, String subject, String keyId) {
        try {

            final KeyPair keyPair = jwk.toKeyPair();

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
