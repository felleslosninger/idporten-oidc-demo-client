package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.idporten.tools.oidc.democlient.config.OIDCIntegrationProperties;
import no.idporten.tools.oidc.democlient.util.WarningLevel;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class SignatureCertificateValidator {

    private final OIDCIntegrationProperties oidcIntegrationProperties;

    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }


    private static <L> List<L> nullSafeIsoDate(@Nullable List<L> list) {
        if (list == null) {
            return List.of();
        }
        return list;
    }

    public static String nullSafeIsoDate(@Nullable Date date) {
        if (date == null) {
            return "";
        }

        try {
            return date.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate().format(DateTimeFormatter.ISO_DATE);
        } catch (DateTimeParseException _) {
            return date.toString();
        }
    }

    public static List<X509Certificate> getSignatureCertChain(@Nullable JWKSet oidcProviderKeys, @Nullable JWT jwt) {
        if (jwt == null || oidcProviderKeys == null) {
            // no-op; need both elements to continue
            return List.of();
        }

        try {
            final JWSHeader jwsHeader = (JWSHeader) jwt.getHeader();
            final String kid = jwsHeader.getKeyID();
            final JWK jwk = oidcProviderKeys.getKeyByKeyId(kid);

            if (jwk == null) {
                log.warn("Unable to validate signing certificate chain, no key found with ID [{}]", kid);
                return List.of();
            }
            return nullSafeIsoDate(jwk.getParsedX509CertChain());

        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
            return List.of();
        }
    }

    public List<ValidationResult> validate(@Nullable List<X509Certificate> x509Chain) {
        final var soonExpiryOffset = Duration.ofDays(oidcIntegrationProperties.getJwksExpiryWarningDays());

        if (isNullOrEmpty(x509Chain)) {
            return List.of(new ValidationResult(WarningLevel.WARNING, "Certificate chain was not found"));
        }

        return x509Chain.stream()
                // validate only first (root) certificate
                .findFirst().stream()
                .map(cert -> this.validateDateRanges(cert, soonExpiryOffset))
                .flatMap(Collection::stream).toList();
    }

    private List<ValidationResult> validateDateRanges(X509Certificate x509, Duration soonExpiryOffset) {
        final var validationResults = new ArrayList<ValidationResult>();

        validationResults.addAll(validateIssuedExpiredDate(x509));

        if (validationResults.isEmpty()) {
            validationResults.addAll(validateSoonExpiry(x509, soonExpiryOffset));
        }
        return validationResults;
    }

    private List<ValidationResult> validateSoonExpiry(X509Certificate x509, Duration soonExpiryOffset) {
        final var soon = Date.from(Instant.now().plus(soonExpiryOffset).truncatedTo(ChronoUnit.DAYS));

        final var results = new ArrayList<ValidationResult>();
        try {
            x509.checkValidity(soon);
        } catch (CertificateExpiredException e) {
            results.add(new ValidationResult(WarningLevel.WARNING, String.format("Certificate expires soon [%s]", nullSafeIsoDate(x509.getNotAfter()))));
        } catch (CertificateNotYetValidException _) {
            return List.of();
        }
        return results;

    }

    private List<ValidationResult> validateIssuedExpiredDate(X509Certificate x509) {
        final var results = new ArrayList<ValidationResult>();
        try {
            x509.checkValidity();
        } catch (CertificateExpiredException e) {
            results.add(new ValidationResult(WarningLevel.ERROR, String.format("Certificate expired [%s]", nullSafeIsoDate(x509.getNotAfter()))));
        } catch (CertificateNotYetValidException e) {
            results.add(new ValidationResult(WarningLevel.WARNING, String.format("Certificate not valid [%s]", nullSafeIsoDate(x509.getNotBefore()))));
        }

        return results;
    }

}
