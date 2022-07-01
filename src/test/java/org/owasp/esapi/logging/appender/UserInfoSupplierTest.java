package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.User;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ESAPI.class})
@PowerMockIgnore("javax.security.*") //Required since User extends javax.security.Principal
public class UserInfoSupplierTest {
    private static final String ESAPI_SESSION_ATTR = "ESAPI_SESSION";
    
    @Rule
    public TestName testName = new TestName();
    
    private Authenticator mockAuth;
    private User mockUser;
    
    @Before
    public void before() throws Exception {
        mockAuth =mock(Authenticator.class); 
        mockUser =mock(User.class);
        
        mockStatic(ESAPI.class);
        when(ESAPI.class, "authenticator").thenReturn(mockAuth);
        
        when(mockUser.getAccountName()).thenReturn(testName.getMethodName() + "-USER");
        
         
        when(mockAuth.getCurrentUser()).thenReturn(mockUser);
    }
    
    @Test
    public void testHappyPath() throws Exception {
        UserInfoSupplier uis = new UserInfoSupplier();
        uis.setLogUserInfo(true);
        String result = uis.get();
        
        assertEquals(testName.getMethodName() + "-USER", result);
        
        verify(mockAuth,times(1)).getCurrentUser();
        verify(mockUser,times(1)).getAccountName();
        
        verifyNoMoreInteractions(mockAuth, mockUser);
    }
    
    @Test
    public void testLogUserOff() {
        UserInfoSupplier uis = new UserInfoSupplier();
        uis.setLogUserInfo(false);
        String result = uis.get();
        
        assertTrue(result.isEmpty());
        verify(mockAuth,times(1)).getCurrentUser();
        
        verifyNoMoreInteractions(mockAuth, mockUser);
    }
    
    @Test
    public void testLogUserNull() {
        when(mockAuth.getCurrentUser()).thenReturn(null);
        UserInfoSupplier uis = new UserInfoSupplier();
        uis.setLogUserInfo(true);
        String result = uis.get();
        
        assertEquals("#ANONYMOUS#", result);
        
        verify(mockAuth,times(1)).getCurrentUser();
        
        verifyNoMoreInteractions(mockAuth,  mockUser);
    }
    
}