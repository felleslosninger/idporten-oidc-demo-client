package no.idporten.tools.oidc.democlient.service;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for creating HTML page with auto-submitting forms.
 */
@Service
public class HtmlFormService {

    public String createHtmlFormAutosubmitPage(URI formAction, Map<String, List<String>> formFields) {
        return htmlHeader()
                + htmlForm(formAction, formFields)
                + htmlFooter();
    }

    private String htmlHeader() {
        return """
                <!DOCTYPE html>

                <html lang="en">
                <head><title>Submit This Form</title></head>
                <body>""";
    }

    private String htmlFooter() {
        return """
                <script type="application/javascript" src="submitform-0.1.2.js"></script>
                </body>
                </html>""";
    }

    public String htmlForm(URI url, Map<String, List<String>> formFields) {
        String inputs = formFields
                .entrySet()
                .stream()
                .filter(entry -> !entry.getValue().isEmpty())
                .filter(entry -> StringUtils.hasText(entry.getValue().getFirst()))
                .map(entry -> "<input type=\"hidden\" name=\"%s\" value=\"%s\">".formatted(
                        HtmlUtils.htmlEscape(entry.getKey()),
                        HtmlUtils.htmlEscape(entry.getValue().getFirst())))
                .collect(Collectors.joining("\n"));
        return """
                <form method="post" enctype="application/x-www-form-urlencoded" action="%s">
                %s
                <input type = "submit" value = "Submit" />
                </form>""".formatted(url, inputs);
    }

}
