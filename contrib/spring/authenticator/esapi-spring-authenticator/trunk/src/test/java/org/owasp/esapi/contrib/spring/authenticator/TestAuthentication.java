package org.owasp.esapi.contrib.spring.authenticator;

import junit.framework.TestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.User;
import org.owasp.esapi.reference.DefaultUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "/applicationContext.xml")
public class TestAuthentication {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private UsernamePasswordAuthenticationFilter filter;

    @Autowired
    private MockAuthenticationStrategy authenticationStrategy;

    @Before
    public void setup() {
        authenticationStrategy.reset();
    }

    @After
    public void cleanup() {
        ESAPI.clearCurrent();
    }

    @Test
    public void testWiring() {
        Assert.assertTrue(MockAuthenticator.class.isInstance(ESAPI.authenticator()));
    }

    @Test
    public void testSuccessfulLogin() {
        setupLoginRequest("admin", "$$$$$$");
        filter.attemptAuthentication(ESAPI.currentRequest(), ESAPI.currentResponse());
    }

    @Test
    public void testIncorrectLogin() {
        setupLoginRequest("admin", "wrong");

        try {
            filter.attemptAuthentication(ESAPI.currentRequest(), ESAPI.currentResponse());
            TestCase.fail();
        } catch (AuthenticationException e) {
        }
    }

    private MockHttpServletRequest setupLoginRequest(String username, String password) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/user/login");
        request.setParameter(ESAPI.securityConfiguration().getUsernameParameterName(), username);
        request.setParameter(ESAPI.securityConfiguration().getPasswordParameterName(), password);
        request.setSession(new MockHttpSession());
        ESAPI.httpUtilities().setCurrentHTTP(request, new MockHttpServletResponse());
        return request;
    }

    @Test
    public void testCreateUser() throws Exception {
        User u = ESAPI.authenticator().createUser("admin", "$$$$$$", "$$$$$$");
        Assert.assertTrue(DefaultUser.class.isInstance(u));
        Assert.assertEquals(u.getAccountName(), "admin");
    }

    public void testChangePassword() throws Exception {
        String newPassword = ESAPI.randomizer().getRandomString(16, EncoderConstants.CHAR_ALPHANUMERICS);
        ESAPI.authenticator().changePassword(ESAPI.authenticator().getCurrentUser(), "$$$$$$", newPassword, newPassword);
        setupLoginRequest("admin", newPassword);
        filter.attemptAuthentication(ESAPI.currentRequest(), ESAPI.currentResponse());
    }

    @Test
    public void testDeleteUser() throws Exception {
        ESAPI.authenticator().removeUser("admin");
        setupLoginRequest("admin", "$$$$$$");
        try {
            filter.attemptAuthentication(ESAPI.currentRequest(), ESAPI.currentResponse());
            TestCase.fail();
        } catch (AccountStatusException e) {
            return;
        }
    }
}
