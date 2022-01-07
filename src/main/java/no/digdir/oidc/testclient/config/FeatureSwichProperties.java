package no.digdir.oidc.testclient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@Data
@Validated
@ConfigurationProperties(prefix = "oidc-test-client.features")
public class FeatureSwichProperties {

    private boolean authorizationDetailsEnabled = false;

}
