package org.owasp.esapi.logging.cleaning;

import org.junit.Assert;
import org.junit.Test;


public class NewlineLogScrubberTest {

    private NewlineLogScrubber scrubber = new NewlineLogScrubber();
    
    @Test
    public void testReplaceR() {
        String cleanedr = scrubber.cleanMessage("\r");
        Assert.assertEquals("_", cleanedr);    
    }
    @Test
    public void testReplaceN() {
        String cleanedc = scrubber.cleanMessage("\n");
        Assert.assertEquals("_", cleanedc);
    }
    
    @Test
    public void testNoReplacement() {
        String cleanedc = scrubber.cleanMessage("This content should remain unchanged");
        Assert.assertEquals("This content should remain unchanged", cleanedc);
    }
    
}
