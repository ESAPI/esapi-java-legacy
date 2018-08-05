package org.owasp.esapi.logging.cleaning;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;


public class CompositeLogScrubberTest {
    
    @Test
    public void testPassthroughOnEmpty() {
        String str = "Testing Content";
        String cleaned = new CompositeLogScrubber(new ArrayList<LogScrubber>()).cleanMessage(str);
        Assert.assertEquals(str, cleaned);
    }
    
    @Test
    public void testListIteration() {
        LogScrubber scrub1 = Mockito.mock(LogScrubber.class);
        LogScrubber scrub2 = Mockito.mock(LogScrubber.class);
        CompositeLogScrubber scrubber = new CompositeLogScrubber(Arrays.asList(scrub1, scrub2));
        
        String msg1 = "start";
        String msg2 = "scrub1 return";
        String msg3 = "scrub2 return";
        
        Mockito.when(scrub1.cleanMessage(msg1)).thenReturn(msg2);
        Mockito.when(scrub2.cleanMessage(msg2)).thenReturn(msg3);
        
        String cleaned = scrubber.cleanMessage(msg1);
        
        Mockito.verify(scrub1, Mockito.times(1)).cleanMessage(msg1);
        Mockito.verify(scrub2, Mockito.times(1)).cleanMessage(msg2);
        
        Assert.assertEquals(msg3, cleaned);
    }

}
