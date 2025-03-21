package no.idporten.tools.oidc.democlient.config;

import com.nimbusds.oauth2.sdk.ResponseMode;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.net.URI;

@Configuration
@Data
@Slf4j
@Validated
@ConfigurationProperties(prefix = "oidc-demo-client.oidc-integration")
public class OIDCIntegrationProperties implements InitializingBean {

    @NotNull
    private URI issuer;

    @NotNull
    private URI redirectUri;

    @NotNull
    private URI postLogoutRedirectUri;

    private URI frontChannelLogoutUri;

    @NotEmpty
    @Pattern(regexp = "^client_secret_basic|client_secret_post|client_secret_jwt|private_key_jwt$")
    private String clientAuthMethod;

    @NotEmpty
    private String clientId;

    private String clientSecret;
    private String clientKeystoreType;
    private String clientKeystoreLocation;
    private String clientKeystorePassword;
    private String clientKeystoreKeyAlias;
    private String clientKeystoreKeyPassword;

    @NotNull
    private ResponseMode responseMode = ResponseMode.QUERY;

    @Min(1)
    private int connectTimeOutMillis;
    @Min(1)
    private int readTimeOutMillis;
    @Min(1)
    private int jwksCacheRefreshMinutes = 5;
    @Min(1)
    private int jwksCacheLifetimeMinutes = 60;

    @Override
    public void afterPropertiesSet() throws Exception {
        if (clientAuthMethod.startsWith("client_secret") && !StringUtils.hasText(clientSecret)) {
            notEmptyForClientAuth("client-secret", clientSecret, clientAuthMethod);
        }
        if (clientAuthMethod.equals("private_key_jwt")) {
            notEmptyForClientAuth("client-keystore-type", clientKeystoreType, clientAuthMethod);
            notEmptyForClientAuth("client-keystore-location", clientKeystoreLocation, clientAuthMethod);
            notEmptyForClientAuth("client-keystore-password", clientKeystorePassword, clientAuthMethod);
            notEmptyForClientAuth("client-keystore-key-alias", clientKeystoreKeyAlias, clientAuthMethod);
            notEmptyForClientAuth("client-keystore-key-password", clientKeystoreKeyPassword, clientAuthMethod);
        }
        frontChannelLogoutUri = URI.create(postLogoutRedirectUri.toString().replaceAll("callback","frontchannel"));
    }

    protected void notEmptyForClientAuth(String property, String value, String clientAuthMethod) {
        if (! StringUtils.hasText(value)) {
            throw new IllegalArgumentException(String.format("Property %s must have a value when using client auth method %s", property, clientAuthMethod));
        }
    }


}
