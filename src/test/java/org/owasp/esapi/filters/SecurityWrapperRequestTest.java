package org.owasp.esapi.filters;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * FIXME: Document intent of class. General Function, purpose of creation, intended feature, etc.
 * Why do people care this exists?
 * 
 * @author Jeremiah
 * @since Jan 3, 2018
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(ESAPI.class)
public class SecurityWrapperRequestTest {

    @Mock
    private HttpServletRequest mockRequest;
    @Mock
    private Validator mockValidator;
    @Mock
    private SecurityConfiguration mockSecConfig;

    @Before
    public void setup() throws Exception {
        PowerMockito.mockStatic(ESAPI.class);
        PowerMockito.when(ESAPI.class, "validator").thenReturn(mockValidator);
        PowerMockito.when(ESAPI.class, "securityConfiguration").thenReturn(mockSecConfig);
    }

    @Test
    public void testGetQueryString() throws IntrusionException, ValidationException {
        String queryString = "queryString";
        int maxLength = 255;

        ArgumentCaptor<String> inputCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> typeCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> lenghtCapture = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Boolean> allowNullCapture = ArgumentCaptor.forClass(Boolean.class);

        PowerMockito.when(mockValidator.getValidInput(Matchers.anyString(), inputCapture.capture(), typeCapture
            .capture(), lenghtCapture.capture(), allowNullCapture.capture())).thenReturn("canonicalized");
        PowerMockito.when(mockSecConfig.getIntProp("HttpUtilities.URILENGTH")).thenReturn(maxLength);
        PowerMockito.when(mockRequest.getQueryString()).thenReturn(queryString);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getQueryString();
        Assert.assertEquals("canonicalized", rval);

        Assert.assertEquals(queryString, inputCapture.getValue());
        Assert.assertEquals("HTTPQueryString", typeCapture.getValue());
        Assert.assertTrue(maxLength == lenghtCapture.getValue().intValue());
        Assert.assertEquals(true, allowNullCapture.getValue());

        Mockito.verify(mockValidator, Mockito.times(1)).getValidInput(Matchers.anyString(), Matchers.anyString(),
            Matchers.anyString(), Matchers.anyInt(), Matchers.anyBoolean());
        Mockito.verify(mockSecConfig, Mockito.times(1)).getIntProp("HttpUtilities.URILENGTH");
        Mockito.verify(mockRequest, Mockito.times(1)).getQueryString();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetQueryStringCanonicalizeException() throws IntrusionException, ValidationException {
        String queryString = "queryString";
        int maxLength = 255;

        ArgumentCaptor<String> inputCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> typeCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> lenghtCapture = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<Boolean> allowNullCapture = ArgumentCaptor.forClass(Boolean.class);

        PowerMockito.when(mockValidator.getValidInput(Matchers.anyString(), inputCapture.capture(), typeCapture
            .capture(), lenghtCapture.capture(), allowNullCapture.capture())).thenThrow(ValidationException.class);
        PowerMockito.when(mockSecConfig.getIntProp("HttpUtilities.URILENGTH")).thenReturn(maxLength);
        PowerMockito.when(mockRequest.getQueryString()).thenReturn(queryString);

        SecurityWrapperRequest request = new SecurityWrapperRequest(mockRequest);
        String rval = request.getQueryString();
        Assert.assertEquals("", rval);

        Assert.assertEquals(queryString, inputCapture.getValue());
        Assert.assertEquals("HTTPQueryString", typeCapture.getValue());
        Assert.assertTrue(maxLength == lenghtCapture.getValue().intValue());
        Assert.assertEquals(true, allowNullCapture.getValue());

        Mockito.verify(mockValidator, Mockito.times(1)).getValidInput(Matchers.anyString(), Matchers.anyString(),
            Matchers.anyString(), Matchers.anyInt(), Matchers.anyBoolean());
        Mockito.verify(mockSecConfig, Mockito.times(1)).getIntProp("HttpUtilities.URILENGTH");
        Mockito.verify(mockRequest, Mockito.times(1)).getQueryString();
    }
}
