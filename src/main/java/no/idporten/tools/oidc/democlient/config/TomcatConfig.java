package no.idporten.tools.oidc.democlient.config;

import org.springframework.boot.tomcat.TomcatConnectorCustomizer;
import org.springframework.context.annotation.Bean;

public class TomcatConfig {
    /**
     * Tomcat 11.0.27 introduced maxLocaleCount (default 10) and rejects requests whose Accept-Language header
     * contains more locales than this. Browsers with long language lists would otherwise get an error.
     */
    static final int MAX_LOCALE_COUNT = 50;

    @Bean
    public TomcatConnectorCustomizer maxLocaleCountCustomizer() {
        return connector -> connector.setMaxLocaleCount(MAX_LOCALE_COUNT);
    }
}
