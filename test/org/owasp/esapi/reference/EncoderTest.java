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
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.io.IOException;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * The Class EncoderTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncoderTest extends TestCase {
    
    /**
	 * Instantiates a new encoder test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public EncoderTest(String testName) {
        super(testName);
    }
    
    /* (non-Javadoc)
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
    	// none
    }
    
    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
    	// none
    }
    
    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(EncoderTest.class);        
        return suite;
    }
    

	/**
	 * Test of canonicalize method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws EncodingException
	 */
	public void testCanonicalize() throws EncodingException {
		System.out.println("canonicalize");
		Encoder instance = ESAPI.encoder();

        assertEquals( "%", instance.canonicalize("%25"));
        assertEquals( "%F", instance.canonicalize("%25F"));
        assertEquals( "<", instance.canonicalize("%3c"));
        assertEquals( "<", instance.canonicalize("%3C"));
        assertEquals( "%X1", instance.canonicalize("%X1"));

        assertEquals( "<", instance.canonicalize("&lt"));
        assertEquals( "<", instance.canonicalize("&LT"));
        assertEquals( "<", instance.canonicalize("&lt;"));
        assertEquals( "<", instance.canonicalize("&LT;"));
        
        assertEquals( "%", instance.canonicalize("&#37;"));
        assertEquals( "%", instance.canonicalize("&#37"));
        assertEquals( "%b", instance.canonicalize("&#37b"));

        assertEquals( "<", instance.canonicalize("&#x3c"));
        assertEquals( "<", instance.canonicalize("&#x3c;"));
        assertEquals( "<", instance.canonicalize("&#x3C"));
        assertEquals( "<", instance.canonicalize("&#X3c"));
        assertEquals( "<", instance.canonicalize("&#X3C"));
        assertEquals( "<", instance.canonicalize("&#X3C;"));

        assertEquals( "<", instance.canonicalize("\\x3c"));        
        assertEquals( "<", instance.canonicalize("\\X3c"));        
        assertEquals( "<", instance.canonicalize("\\x3C"));        
        assertEquals( "<", instance.canonicalize("\\X3C"));        
        assertEquals( "<", instance.canonicalize("\\u003c"));        
        assertEquals( "<", instance.canonicalize("\\U003c"));        
        assertEquals( "<", instance.canonicalize("\\u003C"));        
        assertEquals( "<", instance.canonicalize("\\U003C"));        

        assertEquals( "\0", instance.canonicalize("\\0"));
        assertEquals( "\b", instance.canonicalize("\\b"));
        assertEquals( "\t", instance.canonicalize("\\t"));
        assertEquals( "\n", instance.canonicalize("\\n"));
        assertEquals( ""+(char)0x0b, instance.canonicalize("\\v"));
        assertEquals( "\f", instance.canonicalize("\\f"));
        assertEquals( "\r", instance.canonicalize("\\r"));
        assertEquals( "\'", instance.canonicalize("\\'"));
        assertEquals( "\"", instance.canonicalize("\\\""));
        assertEquals( "\\", instance.canonicalize("\\\\"));

        assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
        assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript\\x3Ealert%28%22hello\\U0022%29%3B%3C%2Fscript%3E") );
        
        // multiple encoding tests, note this uses strict=false flag
        assertEquals( "% & <script> <script>", instance.canonicalize( "%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false ) );
        assertEquals( "< < < < <; <; <;", instance.canonicalize( "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false ) );

        try {
        	assertEquals( "<script", instance.canonicalize("%253Cscript" ) );
        } catch( IntrusionException e ) {
        	// expected
        }
        try {
        	assertEquals( "<script", instance.canonicalize("&#37;3Cscript" ) );
        } catch( IntrusionException e ) {
        	// expected
        }
	}

	/**
	 * Test of normalize method, of class org.owasp.esapi.Validator.
	 * 
	 * @throws ValidationException
	 *             the validation exception
	 */
	public void testNormalize() throws ValidationException {
		System.out.println("normalize");
		assertEquals(ESAPI.encoder().normalize("é à î _ @ \" < > \u20A0"), "e a i _ @ \" < > ");
	}

	
    /**
	 * Test of encodeForHTML method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForHTML() {
        System.out.println("encodeForHTML");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForHTML(null));
        assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
        assertEquals("&lt;script&gt;", instance.encodeForHTML("&lt;script&gt;"));
        assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTML("!@$%()=+{}[]"));
        assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTML("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;") );
        assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
        assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
        assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
    }
    
    /**
	 * Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForHTMLAttribute() {
        System.out.println("encodeForHTMLAttribute");
        Encoder instance = ESAPI.encoder();
        assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
        assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
        assertEquals("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
    }
    
    
    public void testEncodeForCSS() {
    	fail();
    }
    
    
    public void testEncodeForHTMLURI() {
    	fail();
    }
    
    
    /**
	 * Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForJavascript() {
        System.out.println("encodeForJavascript");
        Encoder instance = ESAPI.encoder();
        assertEquals("\\x3Cscript\\x3E", instance.encodeForJavascript("<script>"));
        assertEquals(",.-_ ", instance.encodeForJavascript(",.-_ "));
        assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance.encodeForJavascript("!@$%()=+{}[]"));
        assertEquals( "\\0", instance.encodeForJavascript("\0"));
        assertEquals( "\\b", instance.encodeForJavascript("\b"));
        assertEquals( "\\t", instance.encodeForJavascript("\t"));
        assertEquals( "\\n", instance.encodeForJavascript("\n"));
        assertEquals( "\\v", instance.encodeForJavascript("" + (char)0x0b));
        assertEquals( "\\f", instance.encodeForJavascript("\f"));
        assertEquals( "\\r", instance.encodeForJavascript("\r"));
        assertEquals( "\\'", instance.encodeForJavascript("\'"));
        assertEquals( "\\\"", instance.encodeForJavascript("\""));
        assertEquals( "\\\\", instance.encodeForJavascript("\\"));
    }
    
    /**
	 * Test of encodeForVisualBasicScript method, of class
	 * org.owasp.esapi.Encoder.
	 */
    public void testEncodeForVBScript() {
        System.out.println("encodeForVBScript");
        Encoder instance = ESAPI.encoder();
        assertEquals("\\x3Cscript\\x3E", instance.encodeForJavascript("<script>"));
        assertEquals(",.-_ ", instance.encodeForJavascript(",.-_ "));
        assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance.encodeForJavascript("!@$%()=+{}[]"));
    }
    
    /**
	 * Test of encodeForXPath method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForXPath() {
        System.out.println("encodeForXPath");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#39;or 1&#61;1", instance.encodeForXPath("'or 1=1"));
    }
    

    
    /**
	 * Test of encodeForSQL method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForSQL() {
        System.out.println("encodeForSQL");
        Encoder instance = ESAPI.encoder();
        assertEquals("Single quote", "Jeff'' or ''1''=''1", instance.encodeForSQL("Jeff' or '1'='1"));
    }

    
    /**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForLDAP() {
        System.out.println("encodeForLDAP");
        Encoder instance = ESAPI.encoder();
        assertEquals("No special characters to escape", "Hi This is a test #çà", instance.encodeForLDAP("Hi This is a test #çà"));
        assertEquals("Zeros", "Hi \\00", instance.encodeForLDAP("Hi \u0000"));
        assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # ç à ô", instance.encodeForLDAP("Hi (This) = is * a \\ test # ç à ô"));
    }
    
    /**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForDN() {
        System.out.println("encodeForDN");
        Encoder instance = ESAPI.encoder();
        assertEquals("No special characters to escape", "Helloé", instance.encodeForDN("Helloé"));
        assertEquals("leading #", "\\# Helloé", instance.encodeForDN("# Helloé"));
        assertEquals("leading space", "\\ Helloé", instance.encodeForDN(" Helloé"));
        assertEquals("trailing space", "Helloé\\ ", instance.encodeForDN("Helloé "));
        assertEquals("less than greater than", "Hello\\<\\>", instance.encodeForDN("Hello<>"));
        assertEquals("only 3 spaces", "\\  \\ ", instance.encodeForDN("   "));
        assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", instance.encodeForDN(" Hello\\ + , \"World\" ; "));
    }
    

    /**
	 * Test of encodeForXML method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForXML() {
        System.out.println("encodeForXML");
        Encoder instance = ESAPI.encoder();
        assertEquals(" ", instance.encodeForXML(" "));
        assertEquals("&lt;script&gt;", instance.encodeForXML("<script>"));
        assertEquals(",.-_", instance.encodeForXML(",.-_"));
        assertEquals("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForXML("!@$%()=+{}[]"));
    }
    
    
    
    /**
	 * Test of encodeForXMLAttribute method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForXMLAttribute() {
        System.out.println("encodeForXMLAttribute");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#32;", instance.encodeForXMLAttribute(" "));
        assertEquals("&lt;script&gt;", instance.encodeForXMLAttribute("<script>"));
        assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
        assertEquals("&#32;&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
    }
    
    /**
	 * Test of encodeForURL method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForURL() throws Exception {
        System.out.println("encodeForURL");
        Encoder instance = ESAPI.encoder();
        assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
    }
    
    /**
	 * Test of decodeFromURL method, of class org.owasp.esapi.Encoder.
	 */
    public void testDecodeFromURL() throws Exception {
        System.out.println("decodeFromURL");
        Encoder instance = ESAPI.encoder();
        try {
            assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
            assertEquals("     ", instance.decodeFromURL("+++++") );
        } catch ( Exception e ) {
            fail();
        }
    }
    
    /**
	 * Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.
	 */
    public void testEncodeForBase64() {
        System.out.println("encodeForBase64");
        Encoder instance = ESAPI.encoder();
        try {
            for ( int i=0; i < 100; i++ ) {
                byte[] r = ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes();
                String encoded = instance.encodeForBase64( r, ESAPI.randomizer().getRandomBoolean() );
                byte[] decoded = instance.decodeFromBase64( encoded );
                assertTrue( Arrays.equals( r, decoded ) );
            }
        } catch ( IOException e ) {
            fail();
        }
    }
    
    /**
	 * Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.
	 */
    public void testDecodeFromBase64() {
        System.out.println("decodeFromBase64");
        Encoder instance = ESAPI.encoder();
        for ( int i=0; i < 100; i++ ) {
            try {
                byte[] r = ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes();
                String encoded = instance.encodeForBase64( r, ESAPI.randomizer().getRandomBoolean() );
                byte[] decoded = instance.decodeFromBase64( encoded );
                assertTrue( Arrays.equals( r, decoded ) );
            } catch ( IOException e ) {
                fail();
	        }
        }
        for ( int i=0; i < 100; i++ ) {
            try {
                byte[] r = ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes();
                String encoded = ESAPI.randomizer().getRandomString(1, DefaultEncoder.CHAR_ALPHANUMERICS) + instance.encodeForBase64( r, ESAPI.randomizer().getRandomBoolean() );
	            byte[] decoded = instance.decodeFromBase64( encoded );
	            assertFalse( Arrays.equals(r, decoded) );
            } catch ( IOException e ) {
            	// expected
            }
        }
    }
    
}
