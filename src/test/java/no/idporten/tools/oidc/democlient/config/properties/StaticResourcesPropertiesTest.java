package no.idporten.tools.oidc.democlient.config.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StaticResourcesPropertiesTest {

    @Test
    void testGetDsStaticResourcesBaseUri_defaultValues() {
        StaticResourcesProperties properties = new StaticResourcesProperties();
        assertEquals("https://static.idporten.no/ds/latest", properties.getDsStaticResourcesBaseUri());
    }

    @Test
    void testGetStaticResourcesHost_defaultValue() {
        StaticResourcesProperties properties = new StaticResourcesProperties();
        assertEquals("https://static.idporten.no", properties.getStaticResourcesHost());
    }

    @ParameterizedTest
    @CsvSource({
            "https://static.idporten.no, latest, https://static.idporten.no/ds/latest",
            "https://custom.host.no, v2, https://custom.host.no/ds/v2",
            "https://example.com, v1.0, https://example.com/ds/v1.0",
            "https://cdn.test.no, 3.2.1, https://cdn.test.no/ds/3.2.1"
    })
    void testGetDsStaticResourcesBaseUri(String host, String dsVersion, String expectedUri) {
        StaticResourcesProperties properties = new StaticResourcesProperties();
        properties.setHost(host);
        properties.setDsVersion(dsVersion);
        assertEquals(expectedUri, properties.getDsStaticResourcesBaseUri());
    }
}

