package no.idporten.tools.oidc.democlient.web;

import no.idporten.tools.oidc.democlient.config.properties.FeatureSwitchProperties;
import no.idporten.tools.oidc.democlient.config.properties.ThemeProperties;
import no.idporten.tools.oidc.democlient.service.OIDCIntegrationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@ControllerAdvice
public class TestClientControllerAdvice {

    private final static Logger log = LoggerFactory.getLogger(TestClientControllerAdvice.class);
    private final ThemeProperties themeProperties;
    private final FeatureSwitchProperties featureSwitchProperties;


    public TestClientControllerAdvice(ThemeProperties themeProperties, FeatureSwitchProperties featureSwitchProperties) {
        this.themeProperties = themeProperties;
        this.featureSwitchProperties = featureSwitchProperties;
    }

    @ModelAttribute
    public void addCommonModelAttributes(Model model) {
        model.addAttribute("theme", themeProperties);
        model.addAttribute("features", featureSwitchProperties);
    }


    @ExceptionHandler(Exception.class)
    public String handleException(Exception e, Model model) {
        addCommonModelAttributes(model);
        log.error("Request handling failed", e);
        return "error";
    }

    @ExceptionHandler(OIDCIntegrationException.class)
    public String handleException(OIDCIntegrationException e, Model model) {
        addCommonModelAttributes(model);
        model.addAttribute("message", e.getMessage());
        return "error";
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public String handleException(NoResourceFoundException e, Model model) {
        addCommonModelAttributes(model);
        return "error";
    }





}
