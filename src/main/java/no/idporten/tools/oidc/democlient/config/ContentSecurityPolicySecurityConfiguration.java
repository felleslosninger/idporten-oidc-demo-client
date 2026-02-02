package no.idporten.tools.oidc.democlient.config;

import no.idporten.tools.oidc.democlient.config.properties.OidcDemoClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@EnableConfigurationProperties(OidcDemoClientProperties.class)
public class ContentSecurityPolicySecurityConfiguration {

    public ContentSecurityPolicySecurityConfiguration(OidcDemoClientProperties properties) {
        this.properties = properties;
    }

    private final OidcDemoClientProperties properties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers( headers -> headers.contentSecurityPolicy(c -> c.policyDirectives(String.join(" ", properties.cspHeader()))));
        return http.build();
    }
}