package org.owasp.esapi.waf.actions;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class BlockActionTest {

    @Test
    public void assertDefaultState() {
        BlockAction uit = new BlockAction();
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
    }
    
    @Test
    public void assertSettersGetters_DO_NOTHING() {
        BlockAction uit = new BlockAction();
        uit.setActionNecessary(false);
        uit.setFailed(false);
        
        //Beautiful....
        assertTrue(uit.failedRule());
        assertTrue(uit.isActionNecessary());
    }
}
