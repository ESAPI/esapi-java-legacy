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
package org.owasp.esapi.logging.log4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;

public class Log4JLogBridgeImplTest {

    @Rule
    public TestName testName = new TestName();
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    private LogScrubber mockScrubber = Mockito.mock(LogScrubber.class);
    private LogAppender mockAppender = Mockito.mock(LogAppender.class);
    private Log4JLogLevelHandler mockHandler = Mockito.mock(Log4JLogLevelHandler.class);
    private org.apache.log4j.Logger log4JSpy;
    private Throwable testEx = new Throwable(testName.getMethodName());
    private Log4JLogBridge bridge;

    @Before
    public void setup() {
        Map<Integer, Log4JLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, mockHandler);
        
        org.apache.log4j.Logger wrappedLogger =org.apache.log4j.Logger.getLogger(testName.getMethodName());
        log4JSpy = Mockito.spy(wrappedLogger);
        bridge = new Log4JLogBridgeImpl(mockAppender, mockScrubber, levelLookup);
    }

    @Test
    public void testLogMessageWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup LOG4J level mapping");
        Map<Integer, Log4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Log4JLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(log4JSpy, 0, Logger.EVENT_UNSPECIFIED, "This Should fail");
    }
    
    @Test
    public void testLogMessageAndExceptionWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup LOG4J level mapping");
        Map<Integer, Log4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Log4JLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(log4JSpy, 0, Logger.EVENT_UNSPECIFIED, "This Should fail", testEx);
    }
    
    @Test
    public void testLogMessage() {
    	EventType eventType = Logger.EVENT_UNSPECIFIED;
    	String loggerName = testName.getMethodName();
    	String orignMsg = testName.getMethodName();
    	String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        Mockito.when(mockHandler.isEnabled(log4JSpy)).thenReturn(true);

        bridge.log(log4JSpy, Logger.ALL, eventType, testName.getMethodName());

        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName.getMethodName());
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(log4JSpy);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(log4JSpy), ArgumentMatchers.eq(cleanMsg));
     
        Mockito.verifyNoMoreInteractions(log4JSpy, mockAppender, mockScrubber,mockHandler);
    }

    @Test
    public void testLogErrorMessageWithException() {
    	EventType eventType = Logger.EVENT_UNSPECIFIED;
    	String loggerName = testName.getMethodName();
    	String orignMsg = testName.getMethodName();
    	String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        Mockito.when(mockHandler.isEnabled(log4JSpy)).thenReturn(true);

        bridge.log(log4JSpy, Logger.ALL, eventType, testName.getMethodName(), testEx);

        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName.getMethodName());
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(log4JSpy);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class));

        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(log4JSpy), ArgumentMatchers.eq(cleanMsg), ArgumentMatchers.same(testEx));
     
        Mockito.verifyNoMoreInteractions(log4JSpy, mockAppender, mockScrubber,mockHandler);
    }


    @Test
    public void testDisabledLogMessage() {
        Mockito.when(mockHandler.isEnabled(log4JSpy)).thenReturn(false);

        bridge.log(log4JSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName());

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(log4JSpy);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
    }

    @Test
    public void testDisabledErrorLogWithException() {
        Mockito.when(mockHandler.isEnabled(log4JSpy)).thenReturn(false);

        bridge.log(log4JSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName(), testEx);

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(log4JSpy);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.apache.log4j.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));

    }

}
