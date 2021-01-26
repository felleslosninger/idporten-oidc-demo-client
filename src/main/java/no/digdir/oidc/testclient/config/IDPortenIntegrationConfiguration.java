package no.digdir.oidc.testclient.config;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.net.URI;
import java.util.*;

@Configuration
@Data
@Slf4j
@Validated
@ConfigurationProperties(prefix = "eid-integration.eid-provider")
public class IDPortenIntegrationConfiguration implements InitializingBean {

    private Features features = new Features();

    @NotNull
    private URI issuer;
    @NotNull
    private URI authorizationEndpoint;
    @NotNull
    private URI tokenEndpoint;
    @NotNull
    private URI jwksEndpoint;

    @NotNull
    private URI redirectUri;

    @NotEmpty
    @Pattern(regexp = "^client_secret_basic|client_secret_post|private_key_jwt$")
    private String clientAuthMethod;

    @NotEmpty
    private String clientId;


    private String clientSecret;
    private String clientKeystoreType;
    private String clientKeystoreLocation;
    private String clientKeystorePassword;
    private String clientKeystoreKeyAlias;
    private String clientKeystoreKeyPassword;

    @NotEmpty
    private List<String> scopes;

    private Map<String, String> customParameters = new HashMap<>();

    @Min(1)
    private int connectTimeOutMillis;
    @Min(1)
    private int readTimeOutMillis;
    @Min(1)
    private int jwksCacheRefreshMinutes = 5;
    @Min(1)
    private int jwksCacheLifetimeMinutes = 60;

    @NotEmpty
    private List<String> cancelErrorCodes;

    @Valid
    private IDPortenIntegrationConfiguration.IDTokenConfig idTokenConfig = new IDTokenConfig();

    @Data
    public class IDTokenConfig {

        @NotEmpty
        private Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();

        @NotEmpty
        private String personIdentifierClaim;

        private Map<String, String> requiredClaims = new HashMap<>();

    }

    @Data
    public class Features {

        private boolean readMetadataOnStartup = true;

    }

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
    }

    protected void notEmptyForClientAuth(String property, String value, String clientAuthMethod) {
        if (! StringUtils.hasText(value)) {
            throw new IllegalArgumentException(String.format("Property %s must have a value when using client auth method %s", property, clientAuthMethod));
        }
    }


}
