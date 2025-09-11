package no.idporten.tools.oidc.democlient.service;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertChainValidator {

    public enum ErrorLevel {
        WARN,
        ERROR,
    }

    public Map<WarningLevel, List<String>> validate(List<X509Certificate> x509Chain) {
        if (isNullOrEmpty(x509Chain)) {
            return Map.of(WarningLevel.WARNING, List.of("Signature certificate chain (x5c) is null or empty for your JWT key id"));
        }

        return x509Chain.stream()
                .map(this::checkAndGetValidationErrors)
                .flatMap(map -> map.entrySet().stream())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Map<WarningLevel,List<String>> checkAndGetValidationErrors(X509Certificate x509) {
        final var result = new HashMap<WarningLevel,List<String>>();
        final var errors = validateDateRange(x509);
        if (errors.isEmpty()) {
            return Map.of();
        } else {
            result.putAll(errors);
            return result;
        }
    }

    private Map<WarningLevel, List<String>> validateDateRange(X509Certificate x509) {
        final var errors = new ArrayList<String>();
        try {
            x509.checkValidity();
        } catch (CertificateExpiredException e) {
            errors.add(String.format("Expired at [%s]", x509.getNotAfter().toString()));
        } catch (CertificateNotYetValidException e) {
            errors.add(String.format("Not valid before [%s]", x509.getNotAfter().toString()));
        }
        if (errors.isEmpty()) {
            return Map.of();
        } else {
            return Map.of(WarningLevel.ERROR, errors);
        }
    }

    private static <L> boolean isNullOrEmpty(@Nullable List<L> value) {
        return value == null || value.isEmpty();
    }
}
