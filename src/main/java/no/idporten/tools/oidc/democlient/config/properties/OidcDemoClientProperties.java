package no.idporten.tools.oidc.democlient.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.List;

@ConfigurationProperties(prefix = "oidc-demo-client")
public record OidcDemoClientProperties(
        List<String> cspHeader
) {}
