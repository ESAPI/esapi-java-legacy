package org.owasp.esapi.crypto;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.ValidationException;

public class CryptoTokenTest {
    
    private SecretKey skey1 = null;
    private SecretKey skey2 = null;

    @Before
    public void setUp() throws Exception {
        skey1 = CryptoHelper.generateSecretKey("AES", 128);
        skey2 = CryptoHelper.generateSecretKey("AES", 128);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public final void testCryptoToken() {
        // Test with default CTOR
        CryptoToken ctok = new CryptoToken();
        CTORtest( ctok, null );
    }

    @Test
    public final void testCryptoTokenSecretKey() {
     // Test with default CTOR
        CryptoToken ctok = new CryptoToken(skey1);
        CTORtest( ctok, skey1 );
    }

    private void CTORtest(CryptoToken ctok, SecretKey sk) {
        String token = null;
        try {
            if ( sk == null ) {
                token = ctok.getToken();    // Use default key, Encryptor.MasterKey
            } else {
                token = ctok.getToken(sk);
            }
        } catch (EncryptionException e) {
            fail("Caught unexpected exception on getToken() call: " + e);
        }
        assertNotNull(token);
        assertEquals( ctok.getUserAccountName(), CryptoToken.ANONYMOUS_USER);
        assertFalse( ctok.isExpired() );
        long expTime1 = ctok.getExpiration();
        
        CryptoToken ctok2 = null;
        try {
            if ( sk == null ) {
                ctok2 = new CryptoToken( token );    // Use default key, Encryptor.MasterKey
            } else {
                ctok2 = new CryptoToken( sk, token );
            }
        } catch (EncryptionException e) {
            e.printStackTrace(System.err);
            fail("Caught unexpected exception on CryptoToken CTOR: " + e);
        }
        long expTime2 = ctok2.getExpiration();
        assertTrue("Expected expiration for ctok2 (" + new Date(expTime2) +
                   ") to be later than of ctok (" + new Date(expTime1) + ").",
                   ( expTime2 >= expTime1 ) );
    }

    @Test
    public final void testCryptoTokenSecretKeyString() {
        CryptoToken ctok1 = new CryptoToken(skey1);
        try {
            ctok1.setUserAccountName("kevin.w.wall@gmail.com");
        } catch (ValidationException e) {
            fail("Failed to set user account name because of ValidationException: " + e);
        }
        try {
            ctok1.setAttribute("role-name", "admin");
            ctok1.setAttribute("company", "Qwest");
        } catch (ValidationException e) {
            fail("Failed to set 'role-name' or 'company' attribute because of ValidationException: " + e);
        }
        String token1 = null;
        String token2 = null;
        boolean passedFirst = false;
        try {
            token1 = ctok1.getToken();
            passedFirst = true;
            token2 = ctok1.getToken(skey2);
            assertFalse("Tokens unexpectedly equal!", token1.equals(token2) );
        } catch (EncryptionException e) {
            fail("Failed to retrieve " + (passedFirst ? "1st" : "2nd" ) + " encrypted token");
        }
        CryptoToken ctok2 = null;
        try {
            ctok2 = new CryptoToken(skey1, token1);
            token2 = ctok2.getToken();
            ctok2.setAttribute("company", "CenturyLink");
        } catch (EncryptionException e) {
            fail("Failed to decrypt token1 or re-encrypt token; exception: " + e);
        } catch (ValidationException e) {
            fail("Failed with ValidationException on resetting 'company' attribute: " + e);
        }
        String userName = ctok2.getUserAccountName();
        String roleAttr = ctok2.getAttribute("role-name");
        String company  = ctok2.getAttribute("company");
        assertEquals( userName, "kevin.w.wall@gmail.com");
        assertEquals( roleAttr, "admin");
        assertEquals( company, "CenturyLink");
    }

    @Test
    public final void testExpiration() {
        CryptoToken ctok = new CryptoToken();
        ctok.setExpiration(2);  // 2 seconds
        CryptoToken ctok2 = null;
        try {
            ctok2 = new CryptoToken( ctok.getToken() );
        } catch (EncryptionException e1) {
            fail("Failed to decrypt token");
        }
        assertFalse( ctok.isExpired() );
        assertFalse( ctok2.isExpired() );
        nap(2);

        assertTrue( ctok.isExpired() );
        assertTrue( ctok2.isExpired() );
        
        try {
            ctok2.updateToken(2);
        } catch (EncryptionException e) {
            fail("EncryptionException for token ctok2 by adding additional 2 sec; exception: " + e);
        } catch (ValidationException e) {
            // This would be caused if the token would already be expired even AFTER adding
            // an additional 2 seconds. We don't expect this, but it could happen if the OS
            // causes this process to stall for a bit while running higher priority processes.
            // We don't expect this here though. (Have a test for that below.)
            fail("Failed to update token ctok2 by adding additional 2 sec; exception: " + e);
        }
        assertFalse( ctok2.isExpired() );
        nap(3);
        try {
            ctok2.updateToken(1);
            fail("Expected ValidationException!");
        } catch (EncryptionException e) {
            fail("EncryptionException for token ctok2 by adding additional 2 sec; exception: " + e);
        } catch (ValidationException e) {
            // Probably a bad idea to test this in the following manner as
            // message could change whenever.
            // assertEquals( e.getMessage(), "Token timed out.");
            ;   // Ignore -- in this case, we expect it!
        }
    }

    @Test
    public final void testSetUserAccountName() {
        CryptoToken ctok = new CryptoToken();
        try {
            ctok.setUserAccountName("kevin.w.wall@gmail.com");
            ctok.setUserAccountName("kevin");
            ctok.setUserAccountName("name-with-hyphen");
            ctok.setUserAccountName("x");
            ctok.setUserAccountName("X");
        } catch (ValidationException e) {
            fail("Failed to set user account name because of ValidationException: " + e);
        }
        try {
            ctok.setUserAccountName("");    // Can't be empty
            fail("Failed to throw expected IllegalArgumentException");
        } catch (Throwable t) {
            assertTrue( t instanceof IllegalArgumentException );	// Success
        }
        try {
            ctok.setUserAccountName(null);    // Can't be null
                // Should get one of these, depending on whether or not assertions are enabled.
            fail("Failed to throw expected IllegalArgumentException");
        } catch (ValidationException e) {
            fail("Wrong type of exception thrown (ValidationException): " + e);
        } catch (IllegalArgumentException e) {
            ;   // Success
        }
        try {
            ctok.setUserAccountName("1773g4l");    // Can't start w/ numeric
            fail("Failed to throw expected ValidationException");
        } catch (ValidationException e) {
            ;   // Success
        }
        try {
            ctok.setUserAccountName("invalid/char");    // '/' is not valid.
            fail("Failed to throw expected ValidationException");
        } catch (ValidationException e) {
            ;   // Success
        }
        
    }

    @Test
    public final void testSetExpirationDate() {
        CryptoToken ctok = new CryptoToken();
        try {
            ctok.setExpiration(null);
            fail("Expected IllegalArgumentException on ctok.setExpiration(null).");
        } catch (IllegalArgumentException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }

        try {
            Date now = new Date();
            nap(1);
            ctok.setExpiration(now);
            fail("Expected IllegalArgumentException on ctok.setExpiration(Date) w/ Date in past.");
        } catch (IllegalArgumentException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }

        try {
            ctok.setExpiration(-1);
            fail("Expected IllegalArgumentException on ctok.setExpiration(int) w/ negative interval.");
        } catch (IllegalArgumentException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }

        try {
            Date maxDate = new Date( Long.MAX_VALUE - 1 );
            ctok.setExpiration( maxDate );
            ctok.updateToken(1);
            fail("Expected ArithmeticException on ctok.setExpiration(int).");
        } catch (ArithmeticException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }   
    }


    @Test
    public final void testSetAndGetAttribute() {
        CryptoToken ctok = new CryptoToken();

        // Test case where attr name is empty string. Expect ValidationException
        try {
            ctok.setAttribute("", "someValue");
            fail("Expected ValidationException on ctok.setAttribute().");
        } catch (ValidationException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }
        
        // Test case where attr name does not match regex "[A-Za-z0-9_.-]+".
        // Expect ValidationException.
        try {
            ctok.setAttribute("/my/attr/", "someValue");
            fail("Expected ValidationException on ctok.setAttribute() w/ invalid name.");
        } catch (ValidationException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }
        
        // Test case where attr VALUE is not. Expect ValidationException.
        try {
            ctok.setAttribute("myAttr", null);
            fail("Expected ValidationException on ctok.setAttribute() w/ null value.");
        } catch (ValidationException e) {
            ;   // Success
        } catch (Exception e) {
            fail("Caught unexpected exception: " + e);
        }

        // Test cases that should work. Specifically we want to test cases
        // where attribute values contains each of the values that will
        // be quoted, namely:   '\', '=', and ';'
        try {
            String complexValue = "kwwall;1291183520293;abc=x=yx;xyz=;efg=a;a;;bbb=quotes\\tuff";
            
            ctok.setAttribute("..--__", ""); // Ugly, but legal attr name; empty is legal value.
            ctok.setAttribute("attr1", "\\");
            ctok.setAttribute("attr2", ";");
            ctok.setAttribute("attr3", "=");
            ctok.setAttribute("complexAttr", complexValue);
            String tokenVal = ctok.getToken();
            assertNotNull("tokenVal should not be null", tokenVal);
            
            CryptoToken ctok2 = new CryptoToken(tokenVal);
            String weirdAttr = ctok2.getAttribute("..--__");
            assertTrue("Expecting empty string for value of weird attr, but got: " + weirdAttr,
                       weirdAttr.equals(""));

            String attr1 = ctok2.getAttribute("attr1");
            assertTrue("attr1 has unexpected value of " + attr1, attr1.equals("\\") );

            String attr2 = ctok2.getAttribute("attr2");
            assertTrue("attr2 has unexpected value of " + attr2, attr2.equals(";") );

            String attr3 = ctok2.getAttribute("attr3");
            assertTrue("attr3 has unexpected value of " + attr3, attr3.equals("=") );

            String complexAttr = ctok2.getAttribute("complexAttr");
            assertNotNull(complexAttr);
            assertTrue("complexAttr has unexpected value of " + complexAttr, complexAttr.equals(complexValue) );

        } catch (ValidationException e) {
            fail("Caught unexpected ValidationException: " + e);
        } catch (Exception e) {
            e.printStackTrace(System.err);
            fail("Caught unexpected exception: " + e);
        }
    }

    // Test the following two methods in CryptoToken:
    // public void addAttributes(final Map<String, String> attrs) throws ValidationException
    // public Map<String, String> getAttributes()
    @Test
    public final void testAddandGetAttributes() {
        CryptoToken ctok = new CryptoToken();       
        Map<String, String> origAttrs = null;

        try {
            ctok.setAttribute("attr1", "value1");
            ctok.setAttribute("attr2", "value2");
            origAttrs = ctok.getAttributes();
            origAttrs.put("attr2", "NewValue2");
            String val = ctok.getAttribute("attr2");
            assertTrue("Attribute map not cloned; crypto token attr changed!",
                       val.equals("value2") );  // Confirm original attr2 did not change
            
            origAttrs.put("attr3", "value3");
            origAttrs.put("attr4", "value4");
            ctok.addAttributes(origAttrs);
        } catch (ValidationException e) {
            fail("Caught unexpected ValidationException: " + e);
        }
        try {
            String token = ctok.getToken();
            ctok = new CryptoToken(token);
        } catch (EncryptionException e) {
            fail("Caught unexpected EncryptionException: " + e);
        }
        
        Map<String, String> extractedAttrs = ctok.getAttributes();
        assertTrue("Expected extracted attrs to be equal to original attrs",
                   origAttrs.equals(extractedAttrs));
                
        origAttrs.put("/illegalAttrName/", "someValue");
        try {
            ctok.addAttributes(origAttrs);
            fail("Expected ValidationException");
        } catch (ValidationException e) {
            ;   // Success
        } catch (Exception e) {
            e.printStackTrace(System.err);
            fail("Caught unexpected exception: " + e);
        }
        
        origAttrs.clear();
        CryptoToken ctok2 = null;
        try {
            ctok.clearAttributes();     // Clear any attributes
            ctok2 = new CryptoToken( ctok.getToken() );
        } catch (EncryptionException e) {
            fail("Unexpected EncryptionException");
        }
        
        try {
            ctok2.addAttributes(origAttrs);     // Add (empty) attribute map
        } catch (ValidationException e) {
            fail("Unexpected ValidationException");
        }
        extractedAttrs = ctok2.getAttributes();
        assertTrue("Expected extracted attributes to be empty", extractedAttrs.isEmpty() );
    }

    // Sleep n seconds.
    private static void nap(int n) {
        try {
            System.out.println("Sleeping " + n + " seconds...");
            Thread.sleep( n * 1000 );
        } catch (InterruptedException e) {
            ;   // Ignore
        }
    }
}
