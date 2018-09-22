/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @created 2018
 */
package org.owasp.esapi.logging.slf4j;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest (Slf4JLogFactory.class)
public class Slf4JLogFactoryTest {
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
