package org.owasp.esapi.waf.rules;

import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import org.junit.Test;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;

/**
 * Checks wildcard names in &lt;must-match&gt; rules. See GitHub issue #458.
 */
public class MustMatchRuleTest {

    private static final Pattern ADMIN_PATH = Pattern.compile("^/admin/.*");

    private Action check(MustMatchRule rule, MockHttpServletRequest mock) throws Exception {
        mock.setRequestURI("/admin/config");
        InterceptingHTTPServletRequest request = new InterceptingHTTPServletRequest(mock);
        return rule.check(request, null, null);
    }

    private MustMatchRule rule(String variable, String value) {
        return new MustMatchRule("458", ADMIN_PATH, variable,
                AppGuardianConfiguration.OPERATOR_CONTAINS, value);
    }

    @Test
    public void wildcardHeaderPasses() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addHeader("x-roles", "admin");
        Action action = check(rule("request.headers.x-*", "admin"), mock);
        assertTrue(action instanceof DoNothingAction);
    }

    @Test
    public void wildcardHeaderFails() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addHeader("x-roles", "guest");
        Action action = check(rule("request.headers.x-*", "admin"), mock);
        assertTrue(action instanceof DefaultAction);
    }

    @Test
    public void wildcardParameterPasses() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addParameter("role1", "admin");
        mock.addParameter("role2", "admin");
        Action action = check(rule("request.parameters.role*", "admin"), mock);
        assertTrue(action instanceof DoNothingAction);
    }

    @Test
    public void wildcardParameterFails() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addParameter("role1", "admin");
        mock.addParameter("role2", "guest");
        Action action = check(rule("request.parameters.role*", "admin"), mock);
        assertTrue(action instanceof DefaultAction);
    }

    @Test
    public void plainParameterPasses() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addParameter("role", "admin");
        Action action = check(rule("request.parameters.role", "admin"), mock);
        assertTrue(action instanceof DoNothingAction);
    }

    @Test
    public void plainParameterFails() throws Exception {
        MockHttpServletRequest mock = new MockHttpServletRequest();
        mock.addParameter("role", "guest");
        Action action = check(rule("request.parameters.role", "admin"), mock);
        assertTrue(action instanceof DefaultAction);
    }
}
