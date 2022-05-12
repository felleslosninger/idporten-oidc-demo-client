package no.idporten.tools.oidc.democlient.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When using theme properties")
public class ThemePropertiesTest {

    @DisplayName("then form defaults are set")
    @Test
    void testDefaultDefaults() {
        ThemeProperties themeProperties = new ThemeProperties();
        assertAll(
                () -> assertNotNull(themeProperties.getFormDefaults()),
                () -> assertEquals("openid", themeProperties.getFormDefaults().getScope()),
                () -> assertEquals("low", themeProperties.getFormDefaults().getAcrValue()),
                () -> assertEquals("en", themeProperties.getFormDefaults().getUiLocale())
        );
    }

}
