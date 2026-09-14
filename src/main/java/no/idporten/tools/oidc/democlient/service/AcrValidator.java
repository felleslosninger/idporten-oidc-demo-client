package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Validates the acr claim of an ID token against acr_values_supported from the provider's discovery document.
 */
@Component
@RequiredArgsConstructor
public class AcrValidator {

    private final OIDCProviderMetadata oidcProviderMetadata;

    // acr_values_supported as published by the provider, empty when it publishes none
    public List<String> supportedAcrValues() {
        return Optional.ofNullable(oidcProviderMetadata.getACRs()).orElse(List.of()).stream()
                .map(ACR::getValue)
                .toList();
    }

    public void validate(String acr) {
        List<String> supportedAcrValues = supportedAcrValues();
        if (supportedAcrValues.isEmpty()) {
            // nothing to validate against
            return;
        }
        if (acr == null || !supportedAcrValues.contains(acr)) {
            throw new OIDCIntegrationException(acr == null
                    ? "ID token is missing the acr claim."
                    : acr + ": is not one of acr_values_supported: " + String.join(", ", supportedAcrValues));
        }
    }

}
