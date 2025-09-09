package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.rule.ExpirationRule;
import no.idporten.validator.certificate.rule.ExpirationSoonRule;
import org.springframework.stereotype.Component;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Slf4j
@Component
public class CertificateValidator {
    final Validator validator;

    public CertificateValidator() {
        ValidatorBuilder validatorBuilder = ValidatorBuilder.newInstance();
        validatorBuilder.addRule(new ExpirationRule()).addRule(new ExpirationSoonRule(Duration.of(7, ChronoUnit.DAYS).toMillis()));
        validator = validatorBuilder.build();
    }

    /**
     *
     * @param oidcProviderKeys the configured OIDC authorization servers provider keys to check against
     * @param jwt the JWT which contains key ID, used to lookup the correct certificate chain.
     */
    public void validate(@Nullable JWKSet oidcProviderKeys, @Nullable JWT jwt) {

        if (jwt == null || oidcProviderKeys == null) {
            // no-op; need both elements to continue
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

            final boolean isProd = false;
            if (isNullOrEmpty(x509chain)) {
                if (isProd) {
                    throw new CertificateException("Certificate chain is empty");
                } else {
                    // no-op
                    return;
                }
            }

            for (X509Certificate cert : x509chain) {
                validator.validate(cert);
            }


        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
        } catch (CertificateValidationException | CertificateException e) {
            log.error("Error validating certificate chain", e);
            throw new RuntimeException(e);
        }
    }


    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }

}
