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
 * @created 2019
 */
package org.owasp.esapi.logging.java;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.LogManager;

import org.hamcrest.CustomMatcher;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.appender.LogPrefixAppender;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest (JavaLogFactory.class)
public class JavaLogFactoryTest {
    @Rule
    public TestName testName = new TestName();
    
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    @Test
    public void testConfigurationExceptionOnMissingConfiguration() throws Exception {
        final IOException originException = new IOException(testName.getMethodName());

        LogManager testLogManager = new LogManager() {
            @Override
            public void readConfiguration(InputStream ins) throws IOException, SecurityException {
                throw originException;
            }
        };

        exEx.expectMessage("Failed to load esapi-java-logging.properties");
        exEx.expect(ConfigurationException.class);
       
        exEx.expectCause(new CustomMatcher<Throwable>("Check for IOException") {
            @Override
            public boolean matches(Object item) {
               return item instanceof IOException;
            }
        });

        JavaLogFactory.readLoggerConfiguration(testLogManager);
    }

    @Test
    public void testCreateLoggerByString() {
        Logger logger = new JavaLogFactory().getLogger("test");
        Assert.assertTrue(logger instanceof JavaLogger);
    }

    @Test public void testCreateLoggerByClass() {
        Logger logger = new JavaLogFactory().getLogger(JavaLogBridgeImplTest.class);
        Assert.assertTrue(logger instanceof JavaLogger);
    }

    @Test
    public void checkScrubberWithEncoding() throws Exception {
        ArgumentCaptor<List> delegates = ArgumentCaptor.forClass(List.class);
        PowerMockito.whenNew(CompositeLogScrubber.class).withArguments(delegates.capture()).thenReturn(null);

        //Call to invoke the constructor capture
        JavaLogFactory.createLogScrubber(true);

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
        JavaLogFactory.createLogScrubber(false);

        List<LogScrubber> scrubbers = delegates.getValue();
        Assert.assertEquals(1, scrubbers.size());
        Assert.assertTrue(scrubbers.get(0) instanceof NewlineLogScrubber);
    }

    /**
     * At this time there are no special considerations or handling for the appender
     * creation in this scope. It is expected that the arguments to the internal
     * creation method are passed directly to the constructor of the
     * LogPrefixAppender with no mutation or additional validation.
     */
    @Test
    public void checkPassthroughAppenderConstruct() throws Exception {
        LogPrefixAppender stubAppender = new LogPrefixAppender(true, true, true, true, "");
        ArgumentCaptor<Boolean> userInfoCapture = ArgumentCaptor.forClass(Boolean.class);
        ArgumentCaptor<Boolean> clientInfoCapture = ArgumentCaptor.forClass(Boolean.class);
        ArgumentCaptor<Boolean> serverInfoCapture = ArgumentCaptor.forClass(Boolean.class);
        ArgumentCaptor<Boolean> logAppNameCapture = ArgumentCaptor.forClass(Boolean.class);
        ArgumentCaptor<String> appNameCapture = ArgumentCaptor.forClass(String.class);

        PowerMockito.whenNew(LogPrefixAppender.class).withArguments(userInfoCapture.capture(), clientInfoCapture.capture(), serverInfoCapture.capture(), logAppNameCapture.capture(), appNameCapture.capture()).thenReturn(stubAppender);

        LogAppender appender = JavaLogFactory.createLogAppender(true, true, false, true, testName.getMethodName());

        Assert.assertEquals(stubAppender, appender);
        Assert.assertTrue(userInfoCapture.getValue());
        Assert.assertTrue(clientInfoCapture.getValue());
        Assert.assertFalse(serverInfoCapture.getValue());
        Assert.assertTrue(logAppNameCapture.getValue());
        Assert.assertEquals(testName.getMethodName(), appNameCapture.getValue());    	
    }


}
