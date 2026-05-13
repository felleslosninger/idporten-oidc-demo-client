package no.idporten.tools.oidc.democlient.config.properties;

import lombok.Data;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.util.UriComponentsBuilder;

@Data
@Slf4j
@Validated
@ConfigurationProperties(prefix = "oidc-demo-client.static.resources")
@Configuration
public class StaticResourcesProperties{

    @Getter
    private String host = "https://static.idporten.no";

    /**
     * Version of designsystemet to use.
     */
    @Getter
    private String dsVersion = "latest";

    public String getStaticResourcesHost() {
        return host;
    }
    public String getDsStaticResourcesBaseUri() {
        return UriComponentsBuilder.fromUriString(host)
                .pathSegment("ds")
                .path(dsVersion)
                .build()
                .toString();
    }
}
