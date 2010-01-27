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
import java.util.ArrayList;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.codecs.CSSCodec;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.JavaScriptCodec;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.OracleCodec;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

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

	/**
	 * {@inheritDoc}
	 */
	protected void setUp() throws Exception {
		// none
	}

	/**
	 * {@inheritDoc}s
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


	public void testCanonicalize() throws EncodingException {
		System.out.println("canonicalize");

		ArrayList list = new ArrayList();
		list.add( new HTMLEntityCodec() );
		list.add( new PercentCodec() );
		Encoder instance = new DefaultEncoder( list );

		// Test null paths
		assertEquals( null, instance.canonicalize(null));
		assertEquals( null, instance.canonicalize(null, true));
		assertEquals( null, instance.canonicalize(null, false));

		// test exception paths
		assertEquals( "%", instance.canonicalize("%25", true));
		assertEquals( "%", instance.canonicalize("%25", false));

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

		// percent encoding
		assertEquals( "<", instance.canonicalize("%3c"));
		assertEquals( "<", instance.canonicalize("%3C"));

		// html entity encoding
		assertEquals( "<", instance.canonicalize("&#60"));
		assertEquals( "<", instance.canonicalize("&#060"));
		assertEquals( "<", instance.canonicalize("&#0060"));
		assertEquals( "<", instance.canonicalize("&#00060"));
		assertEquals( "<", instance.canonicalize("&#000060"));
		assertEquals( "<", instance.canonicalize("&#0000060"));
		assertEquals( "<", instance.canonicalize("&#60;"));
		assertEquals( "<", instance.canonicalize("&#060;"));
		assertEquals( "<", instance.canonicalize("&#0060;"));
		assertEquals( "<", instance.canonicalize("&#00060;"));
		assertEquals( "<", instance.canonicalize("&#000060;"));
		assertEquals( "<", instance.canonicalize("&#0000060;"));
		assertEquals( "<", instance.canonicalize("&#x3c"));
		assertEquals( "<", instance.canonicalize("&#x03c"));
		assertEquals( "<", instance.canonicalize("&#x003c"));
		assertEquals( "<", instance.canonicalize("&#x0003c"));
		assertEquals( "<", instance.canonicalize("&#x00003c"));
		assertEquals( "<", instance.canonicalize("&#x000003c"));
		assertEquals( "<", instance.canonicalize("&#x3c;"));
		assertEquals( "<", instance.canonicalize("&#x03c;"));
		assertEquals( "<", instance.canonicalize("&#x003c;"));
		assertEquals( "<", instance.canonicalize("&#x0003c;"));
		assertEquals( "<", instance.canonicalize("&#x00003c;"));
		assertEquals( "<", instance.canonicalize("&#x000003c;"));
		assertEquals( "<", instance.canonicalize("&#X3c"));
		assertEquals( "<", instance.canonicalize("&#X03c"));
		assertEquals( "<", instance.canonicalize("&#X003c"));
		assertEquals( "<", instance.canonicalize("&#X0003c"));
		assertEquals( "<", instance.canonicalize("&#X00003c"));
		assertEquals( "<", instance.canonicalize("&#X000003c"));
		assertEquals( "<", instance.canonicalize("&#X3c;"));
		assertEquals( "<", instance.canonicalize("&#X03c;"));
		assertEquals( "<", instance.canonicalize("&#X003c;"));
		assertEquals( "<", instance.canonicalize("&#X0003c;"));
		assertEquals( "<", instance.canonicalize("&#X00003c;"));
		assertEquals( "<", instance.canonicalize("&#X000003c;"));
		assertEquals( "<", instance.canonicalize("&#x3C"));
		assertEquals( "<", instance.canonicalize("&#x03C"));
		assertEquals( "<", instance.canonicalize("&#x003C"));
		assertEquals( "<", instance.canonicalize("&#x0003C"));
		assertEquals( "<", instance.canonicalize("&#x00003C"));
		assertEquals( "<", instance.canonicalize("&#x000003C"));
		assertEquals( "<", instance.canonicalize("&#x3C;"));
		assertEquals( "<", instance.canonicalize("&#x03C;"));
		assertEquals( "<", instance.canonicalize("&#x003C;"));
		assertEquals( "<", instance.canonicalize("&#x0003C;"));
		assertEquals( "<", instance.canonicalize("&#x00003C;"));
		assertEquals( "<", instance.canonicalize("&#x000003C;"));
		assertEquals( "<", instance.canonicalize("&#X3C"));
		assertEquals( "<", instance.canonicalize("&#X03C"));
		assertEquals( "<", instance.canonicalize("&#X003C"));
		assertEquals( "<", instance.canonicalize("&#X0003C"));
		assertEquals( "<", instance.canonicalize("&#X00003C"));
		assertEquals( "<", instance.canonicalize("&#X000003C"));
		assertEquals( "<", instance.canonicalize("&#X3C;"));
		assertEquals( "<", instance.canonicalize("&#X03C;"));
		assertEquals( "<", instance.canonicalize("&#X003C;"));
		assertEquals( "<", instance.canonicalize("&#X0003C;"));
		assertEquals( "<", instance.canonicalize("&#X00003C;"));
		assertEquals( "<", instance.canonicalize("&#X000003C;"));
		assertEquals( "<", instance.canonicalize("&lt"));
		assertEquals( "<", instance.canonicalize("&lT"));
		assertEquals( "<", instance.canonicalize("&Lt"));
		assertEquals( "<", instance.canonicalize("&LT"));
		assertEquals( "<", instance.canonicalize("&lt;"));
		assertEquals( "<", instance.canonicalize("&lT;"));
		assertEquals( "<", instance.canonicalize("&Lt;"));
		assertEquals( "<", instance.canonicalize("&LT;"));

		assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
		assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", false) );

		// javascript escape syntax
		ArrayList js = new ArrayList();
		js.add( new JavaScriptCodec() );
		instance = new DefaultEncoder( js );
		System.out.println( "JavaScript Decoding" );

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
		assertEquals( "<", instance.canonicalize("\\<"));

		assertEquals( "<", instance.canonicalize("\\u003c"));
		assertEquals( "<", instance.canonicalize("\\U003c"));
		assertEquals( "<", instance.canonicalize("\\u003C"));
		assertEquals( "<", instance.canonicalize("\\U003C"));
		assertEquals( "<", instance.canonicalize("\\x3c"));
		assertEquals( "<", instance.canonicalize("\\X3c"));
		assertEquals( "<", instance.canonicalize("\\x3C"));
		assertEquals( "<", instance.canonicalize("\\X3C"));

		// css escape syntax
		// be careful because some codecs see \0 as null byte
		ArrayList css = new ArrayList();
		css.add( new CSSCodec() );
		instance = new DefaultEncoder( css );
		System.out.println( "CSS Decoding" );
		assertEquals( "<", instance.canonicalize("\\3c"));  // add strings to prevent null byte
		assertEquals( "<", instance.canonicalize("\\03c"));
		assertEquals( "<", instance.canonicalize("\\003c"));
		assertEquals( "<", instance.canonicalize("\\0003c"));
		assertEquals( "<", instance.canonicalize("\\00003c"));
		assertEquals( "<", instance.canonicalize("\\3C"));
		assertEquals( "<", instance.canonicalize("\\03C"));
		assertEquals( "<", instance.canonicalize("\\003C"));
		assertEquals( "<", instance.canonicalize("\\0003C"));
		assertEquals( "<", instance.canonicalize("\\00003C"));
	}


	/**
	 * Test of canonicalize method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws EncodingException
	 */
	public void testDoubleEncodingCanonicalization() throws EncodingException {
		System.out.println("doubleEncodingCanonicalization");
		Encoder instance = ESAPI.encoder();

		// note these examples use the strict=false flag on canonicalize to allow
		// full decoding without throwing an IntrusionException. Generally, you
		// should use strict mode as allowing double-encoding is an abomination.

		// double encoding examples
		assertEquals( "<", instance.canonicalize("&#x26;lt&#59", false )); //double entity
		assertEquals( "\\", instance.canonicalize("%255c", false)); //double percent
		assertEquals( "%", instance.canonicalize("%2525", false)); //double percent

		// double encoding with multiple schemes example
		assertEquals( "<", instance.canonicalize("%26lt%3b", false)); //first entity, then percent
		assertEquals( "&", instance.canonicalize("&#x25;26", false)); //first percent, then entity

		// nested encoding examples
		assertEquals( "<", instance.canonicalize("%253c", false)); //nested encode % with percent
		assertEquals( "<", instance.canonicalize("%%33%63", false)); //nested encode both nibbles with percent
		assertEquals( "<", instance.canonicalize("%%33c", false)); // nested encode first nibble with percent
		assertEquals( "<", instance.canonicalize("%3%63", false));  //nested encode second nibble with percent
		assertEquals( "<", instance.canonicalize("&&#108;t;", false)); //nested encode l with entity
		assertEquals( "<", instance.canonicalize("%2&#x35;3c", false)); //triple percent, percent, 5 with entity

		// nested encoding with multiple schemes examples
		assertEquals( "<", instance.canonicalize("&%6ct;", false)); // nested encode l with percent
		assertEquals( "<", instance.canonicalize("%&#x33;c", false)); //nested encode 3 with entity            

		// multiple encoding tests
		assertEquals( "% & <script> <script>", instance.canonicalize( "%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false ) );
		assertEquals( "< < < < < < <", instance.canonicalize( "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false ) );

		// test strict mode with both mixed and multiple encoding
		try {
			assertEquals( "< < < < < < <", instance.canonicalize( "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B" ) );
		} catch( IntrusionException e ) {
			// expected
		}

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
	 * Test of encodeForHTML method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForHTML() throws Exception {
		Encoder instance = ESAPI.encoder();
		assertEquals(null, instance.encodeForHTML(null));
		assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
		assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", instance.encodeForHTML("&lt;script&gt;"));
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTML("!@$%()=+{}[]"));
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTML(instance.canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;") ) );
		assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
		assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
		assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
	}

	/**
	 * Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForHTMLAttribute() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
		assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
		assertEquals(" &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
	}


	public void testEncodeForCSS() {
		Encoder instance = ESAPI.encoder();
		assertEquals("\\3C script\\3E ", instance.encodeForCSS("<script>"));
		assertEquals(" \\21 \\40 \\24 \\25 \\28 \\29 \\3D \\2B \\7B \\7D \\5B \\5D \\22 ", instance.encodeForCSS(" !@$%()=+{}[]\""));
	}



	/**
	 * Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForJavascript() {
		Encoder instance = ESAPI.encoder();
		assertEquals("\\x3Cscript\\x3E", instance.encodeForJavaScript("<script>"));
		assertEquals(",.-_ ", instance.encodeForJavaScript(",.-_ "));
		assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance.encodeForJavaScript("!@$%()=+{}[]"));
		assertEquals( "\\0", instance.encodeForJavaScript("\0"));
		assertEquals( "\\b", instance.encodeForJavaScript("\b"));
		assertEquals( "\\t", instance.encodeForJavaScript("\t"));
		assertEquals( "\\n", instance.encodeForJavaScript("\n"));
		assertEquals( "\\v", instance.encodeForJavaScript("" + (char)0x0b));
		assertEquals( "\\f", instance.encodeForJavaScript("\f"));
		assertEquals( "\\r", instance.encodeForJavaScript("\r"));
		assertEquals( "\\'", instance.encodeForJavaScript("\'"));
		assertEquals( "\\\"", instance.encodeForJavaScript("\""));
		assertEquals( "\\\\", instance.encodeForJavaScript("\\"));
	}

	public void testEncodeForVBScript() {
		Encoder instance = ESAPI.encoder();
		assertEquals("\"<script\">", instance.encodeForVBScript("<script>"));
		assertEquals(" \"!\"@\"$\"%\"(\")\"=\"+\"{\"}\"[\"]\"\"", instance.encodeForVBScript(" !@$%()=+{}[]\""));
	}

	/**
	 * Test of encodeForXPath method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForXPath() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#x27;or 1&#x3d;1", instance.encodeForXPath("'or 1=1"));
	}



	/**
	 * Test of encodeForSQL method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForSQL() {
		Encoder instance = ESAPI.encoder();

		Codec mySQL1 = new MySQLCodec( MySQLCodec.ANSI_MODE );
		assertEquals("ANSI_MODE", "Jeff'' or ''1''=''1", instance.encodeForSQL(mySQL1, "Jeff' or '1'='1"));

		Codec mySQL2 = new MySQLCodec( MySQLCodec.MYSQL_MODE );
		assertEquals("MYSQL_MODE", "Jeff\\' or \\'1\\'\\=\\'1", instance.encodeForSQL(mySQL2, "Jeff' or '1'='1"));

		Codec oracle = new OracleCodec();
		assertEquals("Oracle", "Jeff'' or ''1''=''1", instance.encodeForSQL(oracle, "Jeff' or '1'='1"));
	}


	/**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForLDAP() {
		Encoder instance = ESAPI.encoder();
		assertEquals("No special characters to escape", "Hi This is a test #��", instance.encodeForLDAP("Hi This is a test #��"));
		assertEquals("Zeros", "Hi \\00", instance.encodeForLDAP("Hi \u0000"));
		assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # � � �", instance.encodeForLDAP("Hi (This) = is * a \\ test # � � �"));
	}

	/**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForDN() {
		Encoder instance = ESAPI.encoder();
		assertEquals("No special characters to escape", "Hello�", instance.encodeForDN("Hello�"));
		assertEquals("leading #", "\\# Hello�", instance.encodeForDN("# Hello�"));
		assertEquals("leading space", "\\ Hello�", instance.encodeForDN(" Hello�"));
		assertEquals("trailing space", "Hello�\\ ", instance.encodeForDN("Hello� "));
		assertEquals("less than greater than", "Hello\\<\\>", instance.encodeForDN("Hello<>"));
		assertEquals("only 3 spaces", "\\  \\ ", instance.encodeForDN("   "));
		assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", instance.encodeForDN(" Hello\\ + , \"World\" ; "));
	}

	public void testEncodeForXMLNull() {
		Encoder instance = ESAPI.encoder();
		assertEquals(null, instance.encodeForXML(null));
	}

	public void testEncodeForXMLSpace() {
		Encoder instance = ESAPI.encoder();
		assertEquals(" ", instance.encodeForXML(" "));
	}

	public void testEncodeForXMLScript() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#x3c;script&#x3e;", instance.encodeForXML("<script>"));
	}

	public void testEncodeForXMLImmune() {
		Encoder instance = ESAPI.encoder();
		assertEquals(",.-_", instance.encodeForXML(",.-_"));
	}

	public void testEncodeForXMLSymbol() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForXML("!@$%()=+{}[]"));
	}

	public void testEncodeForXMLPound() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#xa3;", instance.encodeForXML("\u00A3"));
	}

	public void testEncodeForXMLAttributeNull() {
		Encoder instance = ESAPI.encoder();
		assertEquals(null, instance.encodeForXMLAttribute(null));
	}

	public void testEncodeForXMLAttributeSpace() {
		Encoder instance = ESAPI.encoder();
		assertEquals(" ", instance.encodeForXMLAttribute(" "));
	}

	public void testEncodeForXMLAttributeScript() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#x3c;script&#x3e;", instance.encodeForXMLAttribute("<script>"));
	}

	public void testEncodeForXMLAttributeImmune() {
		Encoder instance = ESAPI.encoder();
		assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
	}

	public void testEncodeForXMLAttributeSymbol() {
		Encoder instance = ESAPI.encoder();
		assertEquals(" &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
	}

	public void testEncodeForXMLAttributePound() {
		Encoder instance = ESAPI.encoder();
		assertEquals("&#xa3;", instance.encodeForXMLAttribute("\u00A3"));
	}

	/**
	 * Test of encodeForURL method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForURL() throws Exception {
		Encoder instance = ESAPI.encoder();
		assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
	}

	/**
	 * Test of decodeFromURL method, of class org.owasp.esapi.Encoder.
	 */
	public void testDecodeFromURL() throws Exception {
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
