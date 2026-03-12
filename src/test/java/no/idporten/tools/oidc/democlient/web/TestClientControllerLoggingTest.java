package no.idporten.tools.oidc.democlient.web;

import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import lombok.Locked;
import lombok.With;
import no.idporten.tools.oidc.democlient.config.OIDCIntegrationTestConfiguration;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static no.idporten.logging.access.common.AccessLogConstants.LOGBACK_VALVE_NAME;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
@ActiveProfiles({"test", "unitporten"})
@Import(OIDCIntegrationTestConfiguration.class)
public class TestClientControllerLoggingTest {

    public static final String ACCESS_JSON_APPENDER_NAME = "accessJsonConsoleAppender"; //ref logback-access.xml

    @MockitoBean
    private JARMValidator jarmValidator;


    @LocalServerPort
    private int port;


    private HttpClient httpClient;

    @BeforeEach
    void setup() {
        httpClient = HttpClient.newHttpClient();
    }


    /* POSITIVE TESTS */

    @Test
    void contextLoads() {
        // smoke-test that config is valid
    }

    @Test
    @DisplayName("Given the Spring context has started, logback should process the console appender")
    void startupShouldContainReferencedAppender(CapturedOutput output) {
        String combinedOutput = output.getOut() + output.getErr();

        assertThat(combinedOutput).isNotBlank();
        assertThat(combinedOutput).contains("Processing appender named [" + ACCESS_JSON_APPENDER_NAME + "]");
        assertThat(combinedOutput).contains("Attaching appender named [" + ACCESS_JSON_APPENDER_NAME + "] to ch.qos.logback.access.tomcat.LogbackValve[" + LOGBACK_VALVE_NAME + "]");
        assertThat(combinedOutput).contains("LogbackValve[" + LOGBACK_VALVE_NAME + "] - Done configuring");
    }


    @Test
    @DisplayName("Given a request, expect access log to contain custom environment fields")
    void shouldIncludeCustomAccessLogProviderFields(CapturedOutput output) throws Exception {
        // when making an HTTP request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/"))
                .GET()
                .build();
        httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // then the access log should contain custom fields added by AccesslogProvider
        Awaitility.await()
                .atMost(Duration.ofSeconds(2))
                .untilAsserted(() -> {
                    assertThat(output.getOut()).contains("\"@type\":\"access\"");
                    assertThat(output.getOut()).contains("\"logtype\":\"tomcat-access\"");
                    assertThat(output.getOut()).contains("\"request_method\":\"GET\"");
                    assertThat(output.getOut()).contains("\"request_uri\":\"/\"");
                    assertThat(output.getOut()).contains("\"status_code\":200");
                    assertThat(output.getOut()).contains("\"application\":\"unitporten-oidc-demo-client\"");
                    assertThat(output.getOut()).contains("\"environment\":\"unitland\"");
                });
    }

    /* NEGATIVE TESTS */

    @Test
    @DisplayName("Given the Spring context has started, expect logs to not contain logback appender errors")
    void startupShouldNeverContainNotReferencedAppender(CapturedOutput output) {
        String combinedOutput = output.getOut() + output.getErr();

        assertThat(combinedOutput).isNotBlank(); // spring should have started
        assertThat(combinedOutput)
                .doesNotContain("Appender named [" + TestClientControllerLoggingTest.ACCESS_JSON_APPENDER_NAME + "] not referenced");
        assertThat(combinedOutput)
                .doesNotContain("Appender named [" + TestClientControllerLoggingTest.ACCESS_JSON_APPENDER_NAME + "] could not be found.");
    }

}
