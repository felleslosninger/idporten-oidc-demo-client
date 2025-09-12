package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public List<ValidationResult> validate(@Nullable List<X509Certificate> x509Chain) {
        if (isNullOrEmpty(x509Chain)) {
            return List.of(new ValidationResult(WarningLevel.WARNING, "Certificate chain was not found"));
        }

        return x509Chain.stream()
                // validate only first (root) certificate
                .findFirst().stream()
                .map(this::validateDateRanges)
                .flatMap(Collection::stream).toList();
    }

    private List<ValidationResult> validateDateRanges(X509Certificate x509) {
        final var validationResults = new ArrayList<ValidationResult>(validateIssuedExpiredDate(x509));

       if(validationResults.isEmpty()) {
           validationResults.addAll(validateSoonExpiry(x509));
       }
       return validationResults;
    }

    private List<ValidationResult> validateSoonExpiry(X509Certificate x509) {
        final var soon = Date.from(Instant.now().plus(Duration.ofDays(7)).truncatedTo(ChronoUnit.DAYS));

        final var results = new ArrayList<ValidationResult>();
        try {
            x509.checkValidity(soon);
        } catch (CertificateExpiredException e) {
            results.add(new ValidationResult(WarningLevel.WARNING, String.format("Certificate expires soon [%s]", safeFormattedDate(x509.getNotBefore()))));
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
            results.add(new ValidationResult(WarningLevel.ERROR, String.format("Certificate expired [%s]", safeFormattedDate(x509.getNotBefore()))));
        } catch (CertificateNotYetValidException e) {
            results.add(new ValidationResult(WarningLevel.WARNING, String.format("Certificate not valid [%s]", safeFormattedDate(x509.getNotBefore()))));
        }

        return results;
    }

    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }


    public static String safeFormattedDate(Date date) {
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
            return nullSafeList(jwk.getParsedX509CertChain());

        } catch (ClassCastException ex) {
            log.warn("Token header is not of type JWSHeader", ex);
            return List.of();
        }
    }

    private static <T> List<T> nullSafeList(List<T> list) {
       if (list == null) {
           return List.of();
       }
       return list;
    }

}
