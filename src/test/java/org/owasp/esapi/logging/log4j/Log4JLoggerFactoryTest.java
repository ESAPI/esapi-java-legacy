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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2019
 */
package org.owasp.esapi.logging.log4j;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggerRepository;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.powermock.reflect.Whitebox;

/**
 * Basic test implementation that verifies that the {@link LogAppender} and
 * {@link LogScrubber} references are applied by the {@link Logger} instances
 * created by the {@link Log4JLoggerFactory}.
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class Log4JLoggerFactoryTest {
    @Mock
    private LogScrubber scrubber;
    @Mock
    private LogAppender appender;
    @Rule
    public TestName testName = new TestName();

    private String logMsg = testName.getMethodName() + "-MESSAGE";
    private Logger logger;

    @Before
    public void configureStaticFactoryState() {
        Log4JLoggerFactory factory = new Log4JLoggerFactory();
        Whitebox.setInternalState(Log4JLoggerFactory.class, "LOG4J_LOG_SCRUBBER", scrubber);
        Whitebox.setInternalState(Log4JLoggerFactory.class, "LOG4J_LOG_APPENDER", appender);

        Mockito.when(scrubber.cleanMessage(logMsg)).thenReturn(logMsg);
        Mockito.when(appender.appendTo(testName.getMethodName(), null, logMsg)).thenReturn(logMsg);

        LoggerRepository mockRepo = Mockito.mock(LoggerRepository.class);
        Mockito.when(mockRepo.isDisabled(ArgumentMatchers.anyInt())).thenReturn(false);

        logger = factory.makeNewLoggerInstance(testName.getMethodName());
        Whitebox.setInternalState(logger, "repository", mockRepo);
        logger.setLevel(Level.ALL);
    }

    @Test
    public void testLogDebug() {
        logger.debug(logMsg);
        Mockito.verify(scrubber, Mockito.times(1)).cleanMessage(logMsg);
        Mockito.verify(appender, Mockito.times(1)).appendTo(testName.getMethodName(), null, logMsg);
    }

    @Test
    public void testLogInfo() {
        logger.info(logMsg);
        Mockito.verify(scrubber, Mockito.times(1)).cleanMessage(logMsg);
        Mockito.verify(appender, Mockito.times(1)).appendTo(testName.getMethodName(), null, logMsg);
    }

    @Test
    public void testLogWarn() {
        logger.warn(logMsg);
        Mockito.verify(scrubber, Mockito.times(1)).cleanMessage(logMsg);
        Mockito.verify(appender, Mockito.times(1)).appendTo(testName.getMethodName(), null, logMsg);
    }

    @Test
    public void testLogError() {
        logger.error(logMsg);
        Mockito.verify(scrubber, Mockito.times(1)).cleanMessage(logMsg);
        Mockito.verify(appender, Mockito.times(1)).appendTo(testName.getMethodName(), null, logMsg);
    }

}
