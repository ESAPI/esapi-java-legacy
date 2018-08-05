package org.owasp.esapi.logging.slf4j;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

@RunWith(PowerMockRunner.class)
@PrepareForTest (Slf4JLogFactory.class)
public class Slf4JLogFactoryTest {
//TODO:  Test to assert the encoder is an html encoder
//TODO:  Assert the immunity list for special slf4j characters
//TODO: Assert the Level mapping content
    @Test
    public void testCreateLoggerByString() {
        Logger logger = new Slf4JLogFactory().getLogger("test");
        Assert.assertTrue(logger instanceof Slf4JLogger);
    }
    
    @Test public void testCreateLoggerByClass() {
        Logger logger = new Slf4JLogFactory().getLogger(Slf4JLogBridgeImplTest.class);
        Assert.assertTrue(logger instanceof Slf4JLogger);
    }
    
    @Test
    public void checkScrubberWithEncoding() throws Exception {
        ArgumentCaptor<List> delegates = ArgumentCaptor.forClass(List.class);
        PowerMockito.whenNew(CompositeLogScrubber.class).withArguments(delegates.capture()).thenReturn(null);
        
        //Call to invoke the constructor capture
        Slf4JLogFactory.createLogScrubber(true);
        
        List<LogScrubber> scrubbers = delegates.getValue();
        Assert.assertEquals(2, scrubbers.size());
        Assert.assertTrue(scrubbers.get(0) instanceof NewlineLogScrubber);
        Assert.assertTrue(scrubbers.get(1) instanceof CodecLogScrubber);
    }
    
    @Test
    public void checkScrubberWithoutEncoding() throws Exception {
        ArgumentCaptor<List> delegates = ArgumentCaptor.forClass(List.class);
        PowerMockito.whenNew(CompositeLogScrubber.class).withArguments(delegates.capture()).thenReturn(null);
        
        //Call to invoke the constructor capture
        Slf4JLogFactory.createLogScrubber(false);
        
        List<LogScrubber> scrubbers = delegates.getValue();
        Assert.assertEquals(1, scrubbers.size());
        Assert.assertTrue(scrubbers.get(0) instanceof NewlineLogScrubber);
    }
}
