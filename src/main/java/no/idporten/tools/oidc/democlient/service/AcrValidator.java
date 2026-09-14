package no.idporten.tools.oidc.democlient.service;

import lombok.RequiredArgsConstructor;
import no.idporten.tools.oidc.democlient.config.properties.ThemeProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.OptionalInt;
import java.util.stream.IntStream;

/**
 * Validates the acr claim of an ID token against the theme configuration: the value must be one of the supported
 * values, and its level of assurance must not be lower than the lowest level the client asked for.
 */
@Component
@RequiredArgsConstructor
public class AcrValidator {

    private final ThemeProperties themeProperties;

    public void validate(String acr, List<String> requestedAcrValues) {
        List<String> supportedAcrValues = themeProperties.getFormDefaults().getSupportedAcrValues();
        if (acr == null || !supportedAcrValues.contains(acr)) {
            throw new OIDCIntegrationException(acr + ": is not one of valid values: " + String.join(", ", supportedAcrValues));
        }
        OptionalInt level = level(acr);
        OptionalInt lowestRequestedLevel = lowestLevel(requestedAcrValues);
        if (level.isPresent() && lowestRequestedLevel.isPresent() && level.getAsInt() < lowestRequestedLevel.getAsInt()) {
            throw new OIDCIntegrationException(acr + ": given when asked for " + String.join(", ", requestedAcrValues));
        }
    }

    // index into acr-levels (ascending), or empty when the value is not ranked
    public OptionalInt level(String acr) {
        List<List<String>> acrLevels = themeProperties.getFormDefaults().getAcrLevels();
        return IntStream.range(0, acrLevels.size())
                .filter(i -> acrLevels.get(i).contains(acr))
                .findFirst();
    }

    private OptionalInt lowestLevel(List<String> acrValues) {
        if (CollectionUtils.isEmpty(acrValues)) {
            return OptionalInt.empty();
        }
        return acrValues.stream()
                .map(this::level)
                .filter(OptionalInt::isPresent)
                .mapToInt(OptionalInt::getAsInt)
                .min();
    }

}
