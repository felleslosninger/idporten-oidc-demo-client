package no.idporten.tools.oidc.democlient.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

@Slf4j
@Configuration
public class ContentSecurityPolicySecurityConfiguration {

    @Value("${oidc-demo-client.csp-header}")
    private String cspHeader;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers( headers -> headers.contentSecurityPolicy(c -> c.policyDirectives(cspHeader)));
        return http.build();
    }
}