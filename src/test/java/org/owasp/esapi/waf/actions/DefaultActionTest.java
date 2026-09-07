package org.owasp.esapi.waf.actions;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DefaultActionTest {

    @Test
    public void assertDefaultState() {
        DefaultAction uit = new DefaultAction();
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
    }
    
    @Test
    public void assertSettersGetters_DO_NOTHING() {
        DefaultAction uit = new DefaultAction();
        uit.setActionNecessary(false);
        uit.setFailed(false);
        
        //Beautiful....
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
    }
}
