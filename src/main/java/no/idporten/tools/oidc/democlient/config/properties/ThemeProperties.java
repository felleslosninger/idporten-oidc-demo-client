package no.idporten.tools.oidc.democlient.config.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@Data
@Slf4j
@Validated
@ConfigurationProperties(prefix = "oidc-demo-client.theme")
public class ThemeProperties {

    private String heading = "Login with ID-porten";
    private String userIdClaim = "sub";
    private FormDefaults formDefaults = new FormDefaults();

    @Data
    public static class FormDefaults {

        private String scope = "openid";
        private String uiLocale = "en";
        private String acrValue = "low";

    }



}
