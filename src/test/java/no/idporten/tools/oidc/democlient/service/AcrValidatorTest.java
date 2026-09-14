package no.idporten.tools.oidc.democlient.service;

import no.idporten.tools.oidc.democlient.config.properties.ThemeProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When validating the acr claim of an ID token")
class AcrValidatorTest {

    private AcrValidator validator;

    @BeforeEach
    void setUp() {
        ThemeProperties themeProperties = new ThemeProperties();
        themeProperties.getFormDefaults().setSupportedAcrValues(List.of(
                "selfregistered-email",
                "eidas-loa-low",
                "idporten-loa-substantial-limited",
                "idporten-loa-substantial",
                "eidas-loa-substantial",
                "idporten-loa-high",
                "eidas-loa-high"));
        themeProperties.getFormDefaults().setAcrLevels(List.of(
                List.of("selfregistered-email"),
                List.of("eidas-loa-low"),
                List.of("idporten-loa-substantial-limited"),
                List.of("idporten-loa-substantial", "eidas-loa-substantial"),
                List.of("idporten-loa-high", "eidas-loa-high")));
        validator = new AcrValidator(themeProperties);
    }

    @Nested
    @DisplayName("and the level is at least what was requested")
    class AcceptedTests {

        @ParameterizedTest(name = "acr {0} is accepted when {1} was requested")
        @CsvSource({
                "idporten-loa-substantial, idporten-loa-substantial",
                "idporten-loa-high, idporten-loa-substantial",
                "idporten-loa-substantial, 'idporten-loa-substantial idporten-loa-high'",
                "eidas-loa-substantial, idporten-loa-substantial",
                "idporten-loa-substantial, eidas-loa-substantial",
                "eidas-loa-high, idporten-loa-high",
                "idporten-loa-substantial-limited, idporten-loa-substantial-limited",
                "selfregistered-email, 'selfregistered-email idporten-loa-high'",
        })
        @DisplayName("then the token is accepted")
        void testAccepted(String acr, String requested) {
            assertDoesNotThrow(() -> validator.validate(acr, requestedAcrValues(requested)));
        }

        @Test
        @DisplayName("then unranked requested values are ignored")
        void testUnrankedRequestedValueIsIgnored() {
            assertDoesNotThrow(() -> validator.validate("idporten-loa-substantial", List.of("Level3")));
        }

        @Test
        @DisplayName("then no requested values means no level to compare against")
        void testNoRequestedValues() {
            assertAll(
                    () -> assertDoesNotThrow(() -> validator.validate("selfregistered-email", List.of())),
                    () -> assertDoesNotThrow(() -> validator.validate("selfregistered-email", null))
            );
        }
    }

    @Nested
    @DisplayName("and the level is lower than what was requested")
    class DowngradeTests {

        @ParameterizedTest(name = "acr {0} is rejected when {1} was requested")
        @CsvSource({
                "idporten-loa-substantial, idporten-loa-high",
                "idporten-loa-substantial-limited, idporten-loa-high",
                "idporten-loa-substantial-limited, idporten-loa-substantial",
                "eidas-loa-low, idporten-loa-substantial",
                "selfregistered-email, idporten-loa-substantial",
                "eidas-loa-substantial, 'idporten-loa-high eidas-loa-high'",
                "idporten-loa-substantial-limited, 'idporten-loa-substantial idporten-loa-high'",
        })
        @DisplayName("then the token is rejected")
        void testRejected(String acr, String requested) {
            OIDCIntegrationException e = assertThrows(OIDCIntegrationException.class,
                    () -> validator.validate(acr, requestedAcrValues(requested)));
            assertAll(
                    () -> assertTrue(e.getMessage().startsWith(acr + ": given when asked for")),
                    () -> assertTrue(e.getMessage().contains(requestedAcrValues(requested).getFirst()))
            );
        }
    }

    @Nested
    @DisplayName("and the value is not supported")
    class UnsupportedTests {

        @Test
        @DisplayName("then an unknown value is rejected even when nothing was requested")
        void testUnknownValue() {
            OIDCIntegrationException e = assertThrows(OIDCIntegrationException.class,
                    () -> validator.validate("Level4", List.of()));
            assertTrue(e.getMessage().startsWith("Level4: is not one of valid values: selfregistered-email"));
        }

        @Test
        @DisplayName("then a missing acr claim is rejected")
        void testMissingValue() {
            assertThrows(OIDCIntegrationException.class, () -> validator.validate(null, List.of("idporten-loa-high")));
        }
    }

    @Nested
    @DisplayName("and looking up levels")
    class LevelTests {

        @Test
        @DisplayName("then equivalent values share a level and unknown values have none")
        void testLevels() {
            assertAll(
                    () -> assertEquals(0, validator.level("selfregistered-email").getAsInt()),
                    () -> assertEquals(validator.level("idporten-loa-substantial"), validator.level("eidas-loa-substantial")),
                    () -> assertTrue(validator.level("idporten-loa-high").getAsInt() > validator.level("idporten-loa-substantial").getAsInt()),
                    () -> assertTrue(validator.level("Level3").isEmpty())
            );
        }
    }

    private static List<String> requestedAcrValues(String spaceSeparated) {
        return Arrays.asList(spaceSeparated.split(" "));
    }

}
