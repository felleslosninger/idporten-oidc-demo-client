package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

// Validates the acr claim of an ID token against acr_values_supported from the provider's discovery document.
// The metadata is read through the supplier on every call, so a value the provider adds later is picked up without a restart.
@Component
@RequiredArgsConstructor
public class AcrValidator {

    private final OIDCProviderMetadataSupplier oidcProviderMetadataSupplier;

    // acr_values_supported as currently published by the provider, empty when it publishes none
    public List<String> supportedAcrValues() {
        return Optional.ofNullable(oidcProviderMetadataSupplier.current().getACRs()).orElse(List.of()).stream()
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
