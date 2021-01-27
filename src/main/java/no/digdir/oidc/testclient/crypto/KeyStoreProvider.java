package no.digdir.oidc.testclient.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ResourceLoader;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Slf4j
public class KeyStoreProvider {

    private KeyStore keyStore;

    public KeyStoreProvider(String type, String location, String password, ResourceLoader resourceLoader) {
        try (InputStream is = new FileInputStream(resourceLoader.getResource(location).getFile())) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(is, password.toCharArray());
            if (log.isInfoEnabled()) {
                log.info("Loaded keystore of type {} from {}", type, location);
            }
            this.keyStore = keyStore;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyStore keyStore() {
        return keyStore;
    }

}
