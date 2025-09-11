package no.idporten.tools.oidc.democlient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@Data
@Validated
@ConfigurationProperties(prefix = "oidc-demo-client.features")
public class FeatureSwitchProperties {

    private boolean authorizationDetailsEnabled = false;
    private boolean usePushedAuthorizationRequests = false;
    private boolean showMissingCertChainEnabled = true;

}
