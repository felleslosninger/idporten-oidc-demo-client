package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
@Component
public class CertificateValidator {

    public void validate(@Nullable JWKSet oidcProviderKeys,@Nullable JWT jwt) {

        if (jwt == null || oidcProviderKeys == null) {
            // no-op
            return;
        }

        try {
            final JWSHeader jwsHeader = (JWSHeader) jwt.getHeader();
            final String kid = jwsHeader.getKeyID();
            final JWK jwk = oidcProviderKeys.getKeyByKeyId(kid);

            if (jwk == null) {
                log.warn("Unable to validate signing certificate chain, no key found with ID [{}]", kid);
                return;
            }

            final List<X509Certificate> x509chain = jwk.getParsedX509CertChain();

            if (x509chain == null || x509chain.isEmpty()) {
                //TODO handle better
                return;
            }

            for (X509Certificate cert : x509chain) {
                final var serial = cert.getSerialNumber();
                final var version = cert.getVersion();
                final var issuerName = cert.getIssuerX500Principal().getName();
                final var signatureAlgorithm = cert.getSigAlgName();
                final var subject = cert.getSubjectX500Principal().getName();
                final var subjectUniqueId = cert.getSubjectUniqueID();
                final var issuerUniqueId = cert.getIssuerUniqueID();
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException e) {
                    throw new OIDCIntegrationException(String.format("Signature certificate JWK expired at [%s] with serial [%f]",DateTimeFormatter.ISO_DATE.format(cert.getNotAfter().toInstant()), serial));
                } catch (CertificateNotYetValidException e) {
                    throw new OIDCIntegrationException(String.format("Signature certificate JWK not yet valid [%s] with serial [%f]",DateTimeFormatter.ISO_DATE.format(cert.getNotBefore().toInstant()), serial));
                }
            }
        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
        }

    }
}
