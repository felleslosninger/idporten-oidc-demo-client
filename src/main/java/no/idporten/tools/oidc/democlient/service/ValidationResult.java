package no.idporten.tools.oidc.democlient.service;

import no.idporten.tools.oidc.democlient.util.WarningLevel;
import org.springframework.lang.NonNull;

import java.util.Collection;

public record ValidationResult(WarningLevel level, String message) {
    public ValidationResult(@NonNull WarningLevel level, @NonNull String message) {
        this.level = level;
        this.message = message;
    }

    public static WarningLevel getHighestLevel(@NonNull Collection<ValidationResult> results) {
        final var levels = results.stream()
                .map(ValidationResult::level)
                .toList();

        if (levels.contains(WarningLevel.ERROR)) {
            return WarningLevel.ERROR;
        } else if (levels.contains(WarningLevel.WARNING)) {
            return WarningLevel.WARNING;
        } else if (levels.contains(WarningLevel.INFO)) {
            return WarningLevel.INFO;
        } else {
            return null;
        }
    }

}

