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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
public class CertChainValidator {
    //TODO: remove
    //final Validator validator;

    public CertChainValidator() {
        //TODO Remove
        /*
        ValidatorBuilder validatorBuilder = ValidatorBuilder.newInstance();
        validator = validatorBuilder
                .addRule(new ExpirationRule())
                .addRule(new ExpirationSoonRule(Duration.of(7, ChronoUnit.DAYS).toMillis()))
                .build();
         */
    }


    public void validate(List<X509Certificate> x509Chain) {
        if (isNullOrEmpty(x509Chain)) {
            return;
        }

        for (X509Certificate cert : x509Chain) {
            final var validationErrors = this.checkAndGetValidationErrors(cert);
            if (validationErrors.isPresent()) {
                throw new OIDCIntegrationException(validationErrors.get());
            }
        }
    }


    /**
     * Refactor or remove this function when idporten-certificate-error-lib has descriptive error messages
     * @param x509 the certificate to validate in X.509 format
     * @return A list of errors, will be empty if none.
     */
    private Optional<String> checkAndGetValidationErrors(X509Certificate x509) {
        final var errors = validateDateRange(x509);
        if (errors.isEmpty()) {
            return Optional.empty();
        } else {
            return Optional.of(String.format("Signature certificate chain (x5c) for the key id (kid) in your JWT is invalid. Check the JWKS configuration with your OIDC provider. Cause:[%s]", String.join(", ", errors)));
        }
    }

    private List<String> validateDateRange(X509Certificate x509) {
        final var errors = new ArrayList<String>();
        try {
            x509.checkValidity();
        } catch (CertificateExpiredException e) {
            errors.add(String.format("Expired at [%s]", x509.getNotAfter().toString()));
        } catch (CertificateNotYetValidException e) {
            errors.add(String.format("Not valid before [%s]", x509.getNotAfter().toString()));
        }
        return errors;
    }


    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }
}
