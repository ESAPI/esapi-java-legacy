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
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.slf4j.Marker;

public class Slf4JLogBridgeImplTest {

    @Rule
    public TestName testName = new TestName();
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    private LogScrubber mockScrubber = Mockito.mock(LogScrubber.class);
    private Slf4JLogLevelHandler mockHandler = Mockito.mock(Slf4JLogLevelHandler.class);
    private org.slf4j.Logger mockSlf4JLogger = Mockito.mock(org.slf4j.Logger.class);
    private Throwable testEx = new Throwable(testName.getMethodName());
    private Slf4JLogBridge bridge;

    @Before
    public void setup() {
        Map<Integer, Slf4JLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, mockHandler);

        bridge = new Slf4JLogBridgeImpl(mockScrubber, levelLookup);
    }

    @Test
    public void testLogMessageWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup SLF4J level mapping");
        Map<Integer, Slf4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Slf4JLogBridgeImpl(mockScrubber, emptyMap).log(mockSlf4JLogger, 0, Logger.EVENT_UNSPECIFIED, "This Should fail");
    }
    
    @Test
    public void testLogMessageAndExceptionWithUnmappedEsapiLevelThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("Unable to lookup SLF4J level mapping");
        Map<Integer, Slf4JLogLevelHandler> emptyMap = Collections.emptyMap();
        new Slf4JLogBridgeImpl(mockScrubber, emptyMap).log(mockSlf4JLogger, 0, Logger.EVENT_UNSPECIFIED, "This Should fail", testEx);
    }
    
    @Test
    public void testLogMessage() {
        String message = testName.getMethodName() + " Cleaned";

        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(true);
        Mockito.when(mockScrubber.cleanMessage(testName.getMethodName())).thenReturn(message);

        bridge.log(mockSlf4JLogger, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName());

        ArgumentCaptor<Marker> markerCapture = ArgumentCaptor.forClass(Marker.class);
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(testName.getMethodName());
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(mockSlf4JLogger), markerCapture.capture(), ArgumentMatchers.matches(message));

        Assert.assertEquals(Logger.EVENT_UNSPECIFIED.toString(), markerCapture.getValue().getName());
    }

    @Test
    public void testLogErrorMessageWithException() {
        String message = testName.getMethodName() + " Cleaned";

        Mockito.when(mockHandler.isEnabled(mockSlf4JLogger)).thenReturn(true);
        Mockito.when(mockScrubber.cleanMessage(testName.getMethodName())).thenReturn(message);

        bridge.log(mockSlf4JLogger, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName.getMethodName(), testEx);

        ArgumentCaptor<Marker> markerCapture = ArgumentCaptor.forClass(Marker.class);
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(testName.getMethodName());
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(mockSlf4JLogger);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(org.slf4j.Logger.class), ArgumentMatchers.any(Marker.class), ArgumentMatchers.any(String.class));

        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(mockSlf4JLogger), markerCapture.capture(), ArgumentMatchers.matches(message), ArgumentMatchers.same(testEx));

        Assert.assertEquals(Logger.EVENT_UNSPECIFIED.toString(), markerCapture.getValue().getName());   
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
