package org.owasp.esapi.waf.actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DoNothingActionTest {

    @Test
    public void assertDefaultState() {
        DoNothingAction uit = new DoNothingAction();
        assertTrue(uit.failedRule());
        assertFalse(uit.isActionNecessary());
    }
    
    @Test
    public void assertSetGetFailed() {
        DoNothingAction uit = new DoNothingAction();
        uit.setFailed(false);
        assertFalse(uit.failedRule());
    }
    
    @Test
    public void assertSetGetActionNecessary_DOES_NOTHING() {
        DoNothingAction uit = new DoNothingAction();
        uit.setActionNecessary(true);
        
        // Room for improvement.
        assertFalse(uit.isActionNecessary());
    }
}
