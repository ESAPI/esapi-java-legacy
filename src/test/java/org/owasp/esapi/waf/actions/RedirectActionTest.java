package org.owasp.esapi.waf.actions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class RedirectActionTest {

    @Test
    public void assertDefaultState() {
        RedirectAction uit = new RedirectAction();
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
        assertNull(uit.getRedirectURL());
    }
    
    @Test
    public void assertSettersGetters() {
        RedirectAction uit = new RedirectAction();
        uit.setActionNecessary(false);
        uit.setFailed(false);
        uit.setRedirectURL("http://going_nowhere.com");
        assertFalse(uit.failedRule());
        assertFalse(uit.isActionNecessary());
        assertEquals("http://going_nowhere.com", uit.getRedirectURL());
    }
}
