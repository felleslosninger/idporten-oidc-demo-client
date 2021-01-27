package no.digdir.oidc.testclient.crypto;

import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

public class KeyProvider {

    private PrivateKey privateKey;
    private Certificate certificate;
    private List<Certificate> certificateChain;

    private PublicKey publicKey;

    public KeyProvider(KeyStore keyStore, String alias, String password) {
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
            certificateChain = Arrays.asList(keyStore.getCertificateChain(alias));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public RSAPublicKey rsaPublicKey() {
        return (RSAPublicKey) publicKey();
    }

    public Certificate certificate() {
        return certificate;
    }

    public List<Certificate> certificateChain() {
        return certificateChain;
    }
}
