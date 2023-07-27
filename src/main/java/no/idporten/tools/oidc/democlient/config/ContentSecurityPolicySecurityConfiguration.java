package no.idporten.tools.oidc.democlient.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;

@Slf4j
@Configuration
public class ContentSecurityPolicySecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers()
            .xssProtection()
            .and()
            .contentSecurityPolicy("style-src 'self' cdn.jsdelivr.net; script-src 'self' cdn.jsdelivr.net; form-action 'self' idporten:7070")
            .and()
            .referrerPolicy()
            .and()
            .permissionsPolicy();
        return http.build();
    }
}