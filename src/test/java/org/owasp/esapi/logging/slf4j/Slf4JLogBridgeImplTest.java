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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestName;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.slf4j.Marker;

public class Slf4JLogBridgeImplTest {

    @Rule
    public TestName testName = new TestName();
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    private LogScrubber mockScrubber = Mockito.mock(LogScrubber.class);
    private LogAppender mockAppender = Mockito.mock(LogAppender.class);
    private Slf4JLogLevelHandler mockHandler = Mockito.mock(Slf4JLogLevelHandler.class);
    private org.slf4j.Logger mockSlf4JLogger = Mockito.mock(org.slf4j.Logger.class);
    private Throwable testEx = new Throwable(testName.getMethodName());
    private Slf4JLogBridge bridge;

    @Before
    public void setup() {
        Map<Integer, Slf4JLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, mockHandler);

        bridge = new Slf4JLogBridgeImpl(mockAppender, mockScrubber, levelLookup);
    }

    @Test
    public void testLogMessageWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup SLF4J level mapping");
        Map<Integer, Slf4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Slf4JLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(mockSlf4JLogger, 0, Logger.EVENT_UNSPECIFIED, "This Should fail");
    }
    
    @Test
    public void testLogMessageAndExceptionWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup SLF4J level mapping");
        Map<Integer, Slf4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Slf4JLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(mockSlf4JLogger, 0, Logger.EVENT_UNSPECIFIED, "This Should fail", testEx);
    }
    
    @Test
    public void testLogMessage() {
    	EventType eventType = Logger.EVENT_UNSPECIFIED;
    	String loggerName = testName.getMethodName() + "-LOGGER";
    	String orignMsg = testName.getMethodName();
    	String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(mockSlf4JLogger.getName()).thenReturn(loggerName);
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        ArgumentCaptor<Marker> markerCapture = ArgumentCaptor.forClass(Marker.class);
        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(true);

        bridge.log(mockSlf4JLogger, Logger.ALL, eventType, testName.getMethodName());

        Mockito.verify(mockSlf4JLogger, Mockito.atLeastOnce()).getName();
        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName.getMethodName());
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(mockSlf4JLogger), markerCapture.capture(), ArgumentMatchers.eq(cleanMsg));
     
        Assert.assertEquals(Logger.EVENT_UNSPECIFIED.toString(), markerCapture.getValue().getName());
        Mockito.verifyNoMoreInteractions(mockSlf4JLogger, mockAppender, mockScrubber,mockHandler);
    }

    @Test
    public void testLogErrorMessageWithException() {
    	EventType eventType = Logger.EVENT_UNSPECIFIED;
    	String loggerName = testName.getMethodName() + "-LOGGER";
    	String orignMsg = testName.getMethodName();
    	String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(mockSlf4JLogger.getName()).thenReturn(loggerName);
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        ArgumentCaptor<Marker> markerCapture = ArgumentCaptor.forClass(Marker.class);
        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(true);

        bridge.log(mockSlf4JLogger, Logger.ALL, eventType, testName.getMethodName(), testEx);

        Mockito.verify(mockSlf4JLogger, Mockito.atLeastOnce()).getName();
        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName.getMethodName());
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class));

        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(mockSlf4JLogger), markerCapture.capture(), ArgumentMatchers.eq(cleanMsg), ArgumentMatchers.same(testEx));
     
        Assert.assertEquals(Logger.EVENT_UNSPECIFIED.toString(), markerCapture.getValue().getName());
        Mockito.verifyNoMoreInteractions(mockSlf4JLogger, mockAppender, mockScrubber,mockHandler);
    }


    @Test
    public void testDisabledLogMessage() {
        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(false);

        bridge.log(mockSlf4JLogger, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName());

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
    }

    @Test
    public void testDisabledErrorLogWithException() {
        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(false);

        bridge.log(mockSlf4JLogger, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName(), testEx);

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));

    }

}
