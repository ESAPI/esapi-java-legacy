package org.owasp.esapi;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;
import org.owasp.esapi.util.ObjFactory;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;


@RunWith(PowerMockRunner.class)
@PrepareForTest({ObjFactory.class})
public class ESAPIContractAPITest {

    @Mock
    private SecurityConfiguration mockSecConfig;
    
    @Mock
    private Validator mockValidator;
    
    @Before
    public void configureStaticContexts() throws Exception {
        PowerMockito.mockStatic(ObjFactory.class);
        PowerMockito.when(ObjFactory.class, "make", ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration")).thenReturn(mockSecConfig);
        PowerMockito.when(ObjFactory.class, "make", ArgumentMatchers.eq("MOCK_TEST_VALIDATOR"), ArgumentMatchers.eq("Validator")).thenReturn(mockValidator);
        
        PowerMockito.when(mockSecConfig.getValidationImplementation()).thenReturn("MOCK_TEST_VALIDATOR");
    }
    
    @Test
    public void testValidatorFromConfiguration() {
        Validator validator = ESAPI.validator();
        Assert.assertEquals("ESAPI Configuration should return Validator as specified by the SecurityConfiguration", mockValidator, validator);
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(1));
        ObjFactory.make(ArgumentMatchers.anyString(), ArgumentMatchers.eq("SecurityConfiguration"));
        
        PowerMockito.verifyStatic(ObjFactory.class, VerificationModeFactory.times(1));
        ObjFactory.make(ArgumentMatchers.eq("MOCK_TEST_VALIDATOR"), ArgumentMatchers.eq("Validator"));
        
        PowerMockito.verifyNoMoreInteractions(ObjFactory.class);
        
        Mockito.verify(mockSecConfig, Mockito.times(1)).getValidationImplementation();
    }
   
}
