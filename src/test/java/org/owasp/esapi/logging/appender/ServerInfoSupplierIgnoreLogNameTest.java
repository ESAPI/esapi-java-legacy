package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.owasp.esapi.ESAPI;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ ESAPI.class })
public class ServerInfoSupplierIgnoreLogNameTest {
    @Rule
    public TestName testName = new TestName();

    private HttpServletRequest request;

    @Before
    public void buildStaticMocks() {
        request = mock(HttpServletRequest.class);
        mockStatic(ESAPI.class);
    }

    @Test
    public void verifyFullOutputIgnoreLogName() throws Exception {
        when(ESAPI.class, "currentRequest").thenReturn(request);
        when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
        when(request.getLocalPort()).thenReturn(99999);

        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(true, testName.getMethodName() + "-APPLICATION");
        sis.setLogServerIp(true);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("LOCAL_ADDR:99999/" + testName.getMethodName() + "-APPLICATION",
                result);
    }

    @Test
    public void verifyOutputNullRequestIgnoreLogName() throws Exception {
        when(ESAPI.class, "currentRequest").thenReturn(null);
        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(true, testName.getMethodName() + "-APPLICATION");
        sis.setLogServerIp(true);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("/" + testName.getMethodName() + "-APPLICATION", result);
    }

    @Test
    public void verifyOutputNoAppNameIgnoreLogName() throws Exception {
        when(ESAPI.class, "currentRequest").thenReturn(request);
        when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
        when(request.getLocalPort()).thenReturn(99999);

        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(false, null);
        sis.setLogServerIp(true);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("LOCAL_ADDR:99999", result);
    }

    @Test
    public void verifyOutputNullAppNameIgnoreLogName() throws Exception {
        when(ESAPI.class, "currentRequest").thenReturn(request);
        when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
        when(request.getLocalPort()).thenReturn(99999);

        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(true, null);
        sis.setLogServerIp(true);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("LOCAL_ADDR:99999/null", result);
    }

    @Test
    public void verifyOutputNoServerIpIgnoreLogName() {
        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(true, testName.getMethodName() + "-APPLICATION");
        sis.setLogServerIp(false);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("/" + testName.getMethodName() + "-APPLICATION", result);
    }

    @Test
    public void verifyOutputNullRequestNoServerIpNullAppNameIgnoreLogName() throws Exception {
        when(ESAPI.class, "currentRequest").thenReturn(null);
        ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
        sis.setLogApplicationName(false, null);
        sis.setLogServerIp(false);
        sis.setLogLogName(false);

        String result = sis.get();
        assertEquals("", result);
    }


}

