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
import no.idporten.validator.certificate.api.ValidatorRule;
import no.idporten.validator.certificate.rule.ExpirationRule;
import no.idporten.validator.certificate.rule.ExpirationSoonRule;
import org.springframework.stereotype.Component;

import java.security.cert.*;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CertChainValidator {
    final Validator validator;

    public CertChainValidator() {
        ValidatorBuilder validatorBuilder = ValidatorBuilder.newInstance();
        validator = validatorBuilder
                .addRule(new ExpirationRule())
                .addRule(new ExpirationSoonRule(Duration.of(7, ChronoUnit.DAYS).toMillis()))
                .build();
    }

    public CertChainValidator(List<ValidatorRule> rules) {
        ValidatorBuilder validatorBuilder = ValidatorBuilder.newInstance();
        for (ValidatorRule rule : rules) {
            validatorBuilder.addRule(rule);
        }
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
                return;
                //TODO: decide to throw a soft error in prod
                //if (isProd) {
                //    throw new OIDCIntegrationException("Signing certificate chain (x5c) for the key id (kid) is missing.  Check the JWKS configuration with your OIDC provider.");
                //} else {
                //    // no-op
                //    return;
                //}
            }

            for (X509Certificate cert : x509chain) {
                //TODO: replace with idporten-certificate-validator-lib when it returns descriptive error messages
                //validator.validate(cert);
                final var validationErrors = this.checkAndGetValidationErrors(cert);
                if (validationErrors.isPresent()) {
                   throw new OIDCIntegrationException(validationErrors.get());
                }
            }
        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
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

    // TODO: remove
    // Not usable until idporten-certificate-validator-lib returns the causes
    private String getSensibleCause(Throwable cause, X509Certificate x509) {

        if (cause == null || x509 == null) {
            return "";
        }

        if (cause instanceof CertificateExpiredException && x509.getNotAfter() != null) {
            return String.format("Certificate expired at [%s]", x509.getNotAfter().toString());
        } else if (cause instanceof CertificateNotYetValidException && x509.getNotBefore() != null) {
            return String.format("Certificate not yet valid: [%s]", x509.getNotAfter().toString());
        } else {
            return cause.getMessage();
        }
    }


    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }
}
