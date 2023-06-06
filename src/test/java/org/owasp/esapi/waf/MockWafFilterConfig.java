package org.owasp.esapi.waf;

import java.util.Map;

import jakarta.servlet.ServletContext;

import org.owasp.esapi.http.MockFilterConfig;

public class MockWafFilterConfig extends MockFilterConfig {

    public MockWafFilterConfig(Map map) {
        super(map);
    }

    public ServletContext getServletContext() {
        return new MockWafServletContext();
    }
}
