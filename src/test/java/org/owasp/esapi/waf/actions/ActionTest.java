package org.owasp.esapi.waf.actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ActionTest {

    @Test
    public void assertDefaultState() {
        Action uit = new Action() {};
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
    }
    
    @Test
    public void assertSettersGetters() {
        Action uit = new Action() {};
        uit.setActionNecessary(false);
        uit.setFailed(false);
        assertFalse(uit.failedRule());
        assertFalse(uit.isActionNecessary());
    }
}
