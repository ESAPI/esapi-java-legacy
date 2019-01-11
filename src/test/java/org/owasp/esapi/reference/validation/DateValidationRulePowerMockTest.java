package org.owasp.esapi.reference.validation;

import java.text.DateFormat;
import java.util.Locale;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.util.ObjFactory;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ObjFactory.class})
public class DateValidationRulePowerMockTest {
    
    @Rule
    public TestName testName = new TestName();
    private Encoder mockEncoder;
    private DateFormat testFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US);
    private DateValidationRule uit;
    @Mock
    private SecurityConfiguration mockSecConfig;
    
    @Before
    public void configureStaticContexts() throws Exception {
        PowerMockito.mockStatic(ObjFactory.class);
        PowerMockito.when(ObjFactory.class, "make", ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration")).thenReturn(mockSecConfig);
        
        mockEncoder = Mockito.mock(Encoder.class);
        testFormat = Mockito.spy(testFormat);
    }
    
    @Test
    public void testSetDateFormatLenientTrueFromCtr() {
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(true);
        
        testFormat.setLenient(false);
        Mockito.reset(testFormat);
        
        uit = new DateValidationRule(testName.getMethodName(), mockEncoder, testFormat);
        
        Assert.assertTrue(testFormat.isLenient());
       
        Mockito.verify(mockSecConfig, Mockito.times(1)).getLenientDatesAccepted();
        Mockito.verify(testFormat, Mockito.times(1)).setLenient(true);
        Mockito.verify(testFormat, Mockito.times(0)).setLenient(false);
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(1));
        ObjFactory.make(ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration"));
        
        PowerMockito.verifyNoMoreInteractions(ObjFactory.class);
        
       
    }
    
    @Test
    public void testSetDateFormatLenientFalseFromCtr() {
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(false);
        
        testFormat.setLenient(true);
        Mockito.reset(testFormat);
        
        uit = new DateValidationRule(testName.getMethodName(), mockEncoder, testFormat);
        
        Assert.assertFalse(testFormat.isLenient());
       
        Mockito.verify(mockSecConfig, Mockito.times(1)).getLenientDatesAccepted();
        Mockito.verify(testFormat, Mockito.times(0)).setLenient(true);
        Mockito.verify(testFormat, Mockito.times(1)).setLenient(false);
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(1));
        ObjFactory.make(ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration"));
        
        PowerMockito.verifyNoMoreInteractions(ObjFactory.class);
    }
    
    @Test
    public void testSetDateFormatLenientFalseFromSetter() {
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(false);
        
        uit = new DateValidationRule(testName.getMethodName(), mockEncoder, testFormat);
        
        //Configuration is lenient=false
        testFormat.setLenient(true);
        Mockito.reset(testFormat, mockSecConfig);
        Assert.assertTrue(testFormat.isLenient());
        
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(false);
        
        uit.setDateFormat(testFormat);
        
        Assert.assertFalse(testFormat.isLenient());
        
        Mockito.verify(mockSecConfig, Mockito.times(1)).getLenientDatesAccepted();
        Mockito.verify(testFormat, Mockito.times(0)).setLenient(true);
        Mockito.verify(testFormat, Mockito.times(1)).setLenient(false);
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(2));
        ObjFactory.make(ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration"));
        
        PowerMockito.verifyNoMoreInteractions(ObjFactory.class);
    }
    
    @Test
    public void testSetDateFormatLenientTrueFromSetter() {
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(true);
        
        uit = new DateValidationRule(testName.getMethodName(), mockEncoder, testFormat);
        
        //Configuration is lenient=true
        testFormat.setLenient(false);
        Mockito.reset(testFormat, mockSecConfig);
        Assert.assertFalse(testFormat.isLenient());
        
        Mockito.when(mockSecConfig.getLenientDatesAccepted()).thenReturn(true);
        
        uit.setDateFormat(testFormat);
        
        Assert.assertTrue(testFormat.isLenient());
        
        Mockito.verify(mockSecConfig, Mockito.times(1)).getLenientDatesAccepted();
        Mockito.verify(testFormat, Mockito.times(1)).setLenient(true);
        Mockito.verify(testFormat, Mockito.times(0)).setLenient(false);
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(2));
        ObjFactory.make(ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration"));
        
        PowerMockito.verifyNoMoreInteractions(ObjFactory.class);
    }
}
