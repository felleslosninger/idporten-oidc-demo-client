package no.digdir.oidc.testclient.web;

import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Component
public class StringToListOfStrings implements Converter<String, List<String>> {

    @Override
    public List<String> convert(String s) {
        if (!StringUtils.hasText(s)) {
            return new ArrayList<>();
        }
        return Arrays.asList(s.split(("\\s*(=>|,|\\s)\\s*")));
    }
}
