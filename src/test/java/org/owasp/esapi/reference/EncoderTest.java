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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.codecs.CSSCodec;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.OracleCodec;
import org.owasp.esapi.codecs.JSONCodec;
import org.owasp.esapi.codecs.PushbackString;
import org.owasp.esapi.codecs.UnixCodec;
import org.owasp.esapi.codecs.WindowsCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * The Class EncoderTest.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncoderTest extends TestCase {

    private static class Conf extends SecurityConfigurationWrapper
    {
        private final List<String> codecList;

        /**
         * @param orig   The original {@code SecurityConfiguration} to use as a basis.
         *               Generally, that will just be:      {@code ESAPI.securityConfiguration()}
         * @param codecsList List of {@code Codec}s to replace {@code Encoder.DefaultCodecList}
         */
        Conf(SecurityConfiguration orig, List<String> codecList)
        {
            super(orig);
            this.codecList = codecList;
        }

        @Override
        public List<String> getDefaultCanonicalizationCodecs()
        {
            return codecList;
        }
    }
    private static final String PREFERRED_ENCODING = "UTF-8";

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
     * @throws Exception
     */
    protected void setUp() throws Exception {
        // none
    }

    /**
     * {@inheritDoc}s
     * @throws Exception
     */
    protected void tearDown() throws Exception {
        ESAPI.override(null); // Restore
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

        ArrayList<String> list = new ArrayList<String>();
        list.add( "HTMLEntityCodec" );
        list.add( "PercentCodec" );
        Encoder instance = new DefaultEncoder( list );

        // Test null paths
        assertEquals( null, instance.canonicalize(null));
        assertEquals( null, instance.canonicalize(null, true));
        assertEquals( null, instance.canonicalize(null, false));
        assertEquals( null, instance.canonicalize(null, true, true));
        assertEquals( null, instance.canonicalize(null, true, false));
        assertEquals( null, instance.canonicalize(null, false, true));
        assertEquals( null, instance.canonicalize(null, false, false));

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
        assertEquals( "&", instance.canonicalize("&amp"));
        assertEquals( "〈", instance.canonicalize("&lang"));

        assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
        assertEquals( "<script>alert(\"hello\");</script>", instance.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", false) );

        // javascript escape syntax
        ArrayList<String> js = new ArrayList<String>();
        js.add( "JavaScriptCodec" );
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
        assertEquals( "\\<", instance.canonicalize("\\<"));

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
        ArrayList<String> css = new ArrayList<String>();
        css.add( "CSSCodec" );
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

        //enforce multiple and mixed encoding detection
        try {
            instance.canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", true, true);
            fail("Multiple and mixed encoding not detected");
        } catch (IntrusionException ie) {}

        //enforce multiple but not mixed encoding detection
        try {
            instance.canonicalize("%252525253C", true, false);
            fail("Multiple encoding not detected");
        } catch (IntrusionException ie) {}

        //enforce mixed but not multiple encoding detection
        try {
            instance.canonicalize("%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false, true);
            fail("Mixed encoding not detected");
        } catch (IntrusionException ie) {}

        //enforce niether mixed nor multiple encoding detection -should canonicalize but not throw an error
        assertEquals( "< < < < < < <", instance.canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B",
                                                             false, false));

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
     *
     * @throws Exception
     */
    public void testEncodeForHTML() throws Exception {
        System.out.println("encodeForHTML");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForHTML(null));
        // test invalid characters are replaced with spaces
        assertEquals("a&#xfffd;b&#xfffd;c&#xfffd;d&#xfffd;e&#xfffd;f&#x9;g", instance.encodeForHTML("a" + (char)0 + "b" + (char)4 + "c" + (char)128 + "d" + (char)150 + "e" +(char)159 + "f" + (char)9 + "g"));

        assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
        assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", instance.encodeForHTML("&lt;script&gt;"));
        assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTML("!@$%()=+{}[]"));
        String canonicalized = instance.canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;");
        assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTML( canonicalized ) );
        assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
        assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
        assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
        assertEquals("" + (char)12345 + (char)65533 + (char)1244, "" + (char)12345 + (char)65533 + (char)1244 );
    }

    /**
     * Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForHTMLAttribute() {
        System.out.println("encodeForHTMLAttribute");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForHTMLAttribute(null));
        assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
        assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
        assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
    }


    /**
     *
     */
    public void testencodeForCSS() {
        System.out.println("encodeForCSS");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForCSS(null));
        assertEquals("\\3c script\\3e ", instance.encodeForCSS("<script>"));
        assertEquals("\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ", instance.encodeForCSS("!@$%()=+{}[]"));
        assertEquals("#f00", instance.encodeForCSS("#f00"));
        assertEquals("#123456", instance.encodeForCSS("#123456"));
        assertEquals("#abcdef", instance.encodeForCSS("#abcdef"));
        assertEquals("red", instance.encodeForCSS("red"));
    }

    public void testCSSTripletLeadString() {
        System.out.println("CSSTripletLeadString");
        Encoder instance = ESAPI.encoder();
        assertEquals("rgb(255,255,255)\\21 ", instance.encodeForCSS("rgb(255,255,255)!"));
        assertEquals("rgb(25%,25%,25%)\\21 ", instance.encodeForCSS("rgb(25%,25%,25%)!"));
    }
    public void testCSSTripletTailString() {
        System.out.println("CSSTripletTailString");
        Encoder instance = ESAPI.encoder();
        assertEquals("\\24 field\\3d rgb(255,255,255)\\21 ", instance.encodeForCSS("$field=rgb(255,255,255)!"));
        assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 ", instance.encodeForCSS("$field=rgb(25%,25%,25%)!"));
    }
    public void testCSSTripletStringPart() {
        System.out.println("CSSTripletStringPart");
        Encoder instance = ESAPI.encoder();
        assertEquals("\\24 field\\3d rgb(255,255,255)\\21 ", instance.encodeForCSS("$field=rgb(255,255,255)!"));
        assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 ", instance.encodeForCSS("$field=rgb(25%,25%,25%)!"));
    }
    public void testCSSTripletStringMultiPart() {
        System.out.println("CSSTripletMultiPart");
        Encoder instance = ESAPI.encoder();
        assertEquals("\\24 field\\3d rgb(255,255,255)\\21 \\20 \\24 field\\3d rgb(255,255,255)\\21 ", instance.encodeForCSS("$field=rgb(255,255,255)! $field=rgb(255,255,255)!"));
        assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 \\20 \\24 field\\3d rgb(25%,25%,25%)\\21 ", instance.encodeForCSS("$field=rgb(25%,25%,25%)! $field=rgb(25%,25%,25%)!"));
        assertEquals("\\24 field\\3d rgb(255,255,255)\\21 \\20 \\24 field\\3d rgb(25%,25%,25%)\\21 ", instance.encodeForCSS("$field=rgb(255,255,255)! $field=rgb(25%,25%,25%)!"));
    }


    /**
     * Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJavascript() {
        System.out.println("encodeForJavascript");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForJavaScript(null));
        assertEquals("\\x3Cscript\\x3E", instance.encodeForJavaScript("<script>"));
        assertEquals(",.\\x2D_\\x20", instance.encodeForJavaScript(",.-_ "));
        assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance.encodeForJavaScript("!@$%()=+{}[]"));
        // assertEquals( "\\0", instance.encodeForJavaScript("\0"));
        // assertEquals( "\\b", instance.encodeForJavaScript("\b"));
        // assertEquals( "\\t", instance.encodeForJavaScript("\t"));
        // assertEquals( "\\n", instance.encodeForJavaScript("\n"));
        // assertEquals( "\\v", instance.encodeForJavaScript("" + (char)0x0b));
        // assertEquals( "\\f", instance.encodeForJavaScript("\f"));
        // assertEquals( "\\r", instance.encodeForJavaScript("\r"));
        // assertEquals( "\\'", instance.encodeForJavaScript("\'"));
        // assertEquals( "\\\"", instance.encodeForJavaScript("\""));
        // assertEquals( "\\\\", instance.encodeForJavaScript("\\"));
    }

    /**
     *
     */
    public void testEncodeForVBScript() {
        System.out.println("encodeForVBScript");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForVBScript(null));
        assertEquals( "chrw(60)&\"script\"&chrw(62)", instance.encodeForVBScript("<script>"));
        assertEquals( "x\"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)", instance.encodeForVBScript("x !@$%()=+{}[]"));
        assertEquals( "alert\"&chrw(40)&chrw(39)&\"ESAPI\"&chrw(32)&\"test\"&chrw(33)&chrw(39)&chrw(41)", instance.encodeForVBScript("alert('ESAPI test!')" ));
        assertEquals( "jeff.williams\"&chrw(64)&\"aspectsecurity.com", instance.encodeForVBScript("jeff.williams@aspectsecurity.com"));
        assertEquals( "test\"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&\"test", instance.encodeForVBScript("test <> test" ));
    }


    /**
     * Test of encodeForXPath method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForXPath() {
        System.out.println("encodeForXPath");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForXPath(null));
        assertEquals("&#x27;or 1&#x3d;1", instance.encodeForXPath("'or 1=1"));
    }



    /**
     * Test of encodeForSQL method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForSQL() {
        System.out.println("encodeForSQL");
        Encoder instance = ESAPI.encoder();

        Codec mySQL1 = new MySQLCodec( MySQLCodec.ANSI_MODE );
        assertEquals("ANSI_MODE", null, instance.encodeForSQL(mySQL1, null));
        assertEquals("ANSI_MODE", "Jeff'' or ''1''=''1", instance.encodeForSQL(mySQL1, "Jeff' or '1'='1"));

        Codec mySQL2 = new MySQLCodec( MySQLCodec.MYSQL_MODE );
        assertEquals("MYSQL_MODE", null, instance.encodeForSQL(mySQL2, null));
        assertEquals("MYSQL_MODE", "Jeff\\' or \\'1\\'\\=\\'1", instance.encodeForSQL(mySQL2, "Jeff' or '1'='1"));

        Codec oracle = new OracleCodec();
        assertEquals("Oracle", null, instance.encodeForSQL(oracle, null));
        assertEquals("Oracle", "Jeff'' or ''1''=''1", instance.encodeForSQL(oracle, "Jeff' or '1'='1"));
    }

    public void testMySQLANSIModeQuoteInjection() {
        System.out.println("mySQLANSIModeQuoteInjection");
        Encoder instance = ESAPI.encoder();
        Codec c = new MySQLCodec(MySQLCodec.Mode.ANSI);
        //No special handling is required for double quotes in ANSI_Quotes mode
        assertEquals("MySQL Ansi Quote Injection Bug", "\" or 1=1 -- -", instance.encodeForSQL(c, "\" or 1=1 -- -"));
    }


    /**
     * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
     *
     * Additional tests: https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
     */
    public void testEncodeForLDAP() {
        System.out.println("encodeForLDAP");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForLDAP(null));
        assertEquals("No special characters to escape", "Hi This is a test", instance.encodeForLDAP("Hi This is a test"));
        assertEquals("No special characters to escape", "Hi This is a test \u0007f", instance.encodeForLDAP("Hi This is a test \u0007f"));
        assertEquals("Special characters to escape", "Hi This is a test \\c2\\80", instance.encodeForLDAP("Hi This is a test \u0080"));
        assertEquals("Special characters to escape", "Hi This is a test \\c3\\bf", instance.encodeForLDAP("Hi This is a test \u00FF"));
        assertEquals("Special characters to escape", "Hi This is a test \\df\\bf", instance.encodeForLDAP("Hi This is a test \u07FF"));
        assertEquals("Special characters to escape", "Hi This is a test \\e0\\a0\\80", instance.encodeForLDAP("Hi This is a test \u0800"));
        assertEquals("Special characters to escape", "Hi This is a test \\e0\\a3\\bf", instance.encodeForLDAP("Hi This is a test \u08FF"));
        assertEquals("Special characters to escape", "Hi This is a test \\e7\\bf\\bf", instance.encodeForLDAP("Hi This is a test \u7FFF"));
        assertEquals("Special characters to escape", "Hi This is a test \\e8\\80\\80", instance.encodeForLDAP("Hi This is a test \u8000"));
        assertEquals("Special characters to escape", "Hi This is a test \\e8\\bf\\bf", instance.encodeForLDAP("Hi This is a test \u8FFF"));
        assertEquals("Special characters to escape", "Hi This is a test \\ef\\bf\\bf", instance.encodeForLDAP("Hi This is a test \uFFFF"));
        assertEquals("Special characters to escape", "Hi This is a test #\\ef\\bf\\bd\\ef\\bf\\bd", instance.encodeForLDAP("Hi This is a test #��"));
        assertEquals("NUL", "Hi \\00", instance.encodeForLDAP("Hi \u0000"));
        assertEquals("LPAREN", "Hi \\28", instance.encodeForLDAP("Hi ("));
        assertEquals("RPAREN", "Hi \\29", instance.encodeForLDAP("Hi )"));
        assertEquals("ASTERISK", "Hi \\2a", instance.encodeForLDAP("Hi *"));
        assertEquals("SLASH", "Hi \\2f", instance.encodeForLDAP("Hi /"));
        assertEquals("ESC", "Hi \\5c", instance.encodeForLDAP("Hi \\"));
        assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # \\ef\\bf\\bd \\ef\\bf\\bd \\ef\\bf\\bd", instance.encodeForLDAP("Hi (This) = is * a \\ test # � � �"));
        assertEquals("Hi \\28This\\29 =", instance.encodeForLDAP("Hi (This) ="));
        assertEquals("Forward slash for \\2fMicrosoft\\2f \\2fAD\\2f", instance.encodeForLDAP("Forward slash for /Microsoft/ /AD/"));
        assertEquals("RFC 4515, Section 4", "(cn=Babs Jensen)", "(cn=" + instance.encodeForLDAP("Babs Jensen") + ")");
    }

    /**
     * Test of encodeForLDAP method with without encoding wildcard characters, of class org.owasp.esapi.Encoder.
     *
     * Additional tests: https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
     */
    public void testEncodeForLDAPWithoutEncodingWildcards() {
        System.out.println("encodeForLDAPWithoutEncodingWildcards");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForLDAP(null, false));
        assertEquals("No special characters to escape", "Hi This is a test", instance.encodeForLDAP("Hi This is a test"));
        assertEquals("No special characters to escape", "Hi This is a test \u0007f", instance.encodeForLDAP("Hi This is a test \u0007f", false));
        assertEquals("Special characters to escape", "Hi This is a test \\c2\\80", instance.encodeForLDAP("Hi This is a test \u0080", false));
        assertEquals("Special characters to escape", "Hi This is a test \\c3\\bf", instance.encodeForLDAP("Hi This is a test \u00FF", false));
        assertEquals("Special characters to escape", "Hi This is a test \\df\\bf", instance.encodeForLDAP("Hi This is a test \u07FF", false));
        assertEquals("Special characters to escape", "Hi This is a test \\e0\\a0\\80", instance.encodeForLDAP("Hi This is a test \u0800", false));
        assertEquals("Special characters to escape", "Hi This is a test \\e0\\a3\\bf", instance.encodeForLDAP("Hi This is a test \u08FF", false));
        assertEquals("Special characters to escape", "Hi This is a test \\e7\\bf\\bf", instance.encodeForLDAP("Hi This is a test \u7FFF", false));
        assertEquals("Special characters to escape", "Hi This is a test \\e8\\80\\80", instance.encodeForLDAP("Hi This is a test \u8000", false));
        assertEquals("Special characters to escape", "Hi This is a test \\e8\\bf\\bf", instance.encodeForLDAP("Hi This is a test \u8FFF", false));
        assertEquals("Special characters to escape", "Hi This is a test \\ef\\bf\\bf", instance.encodeForLDAP("Hi This is a test \uFFFF", false));
        assertEquals("Special characters to escape", "Hi This is a test #\\ef\\bf\\bd\\ef\\bf\\bd", instance.encodeForLDAP("Hi This is a test #��", false));
        assertEquals("NUL", "Hi \\00", instance.encodeForLDAP("Hi \u0000", false));
        assertEquals("LPAREN", "Hi \\28", instance.encodeForLDAP("Hi (", false));
        assertEquals("RPAREN", "Hi \\29", instance.encodeForLDAP("Hi )", false));
        assertEquals("ASTERISK", "Hi *", instance.encodeForLDAP("Hi *", false));
        assertEquals("SLASH", "Hi \\2f", instance.encodeForLDAP("Hi /", false));
        assertEquals("ESC", "Hi \\5c", instance.encodeForLDAP("Hi \\", false));
        assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is * a \\5c test # \\ef\\bf\\bd \\ef\\bf\\bd \\ef\\bf\\bd", instance.encodeForLDAP("Hi (This) = is * a \\ test # � � �", false));
        assertEquals("Forward slash for \\2fMicrosoft\\2f \\2fAD\\2f", instance.encodeForLDAP("Forward slash for /Microsoft/ /AD/"));
        assertEquals("RFC 4515, Section 4", "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
            "(&(objectClass=" + instance.encodeForLDAP("Person") + ")(|(sn=" + instance.encodeForLDAP("Jensen") + ")(cn=" + instance.encodeForLDAP("Babs J*", false) + ")))");
        assertEquals("RFC 4515, Section 4", "(o=univ*of*mich*)",
            "(o=" + instance.encodeForLDAP("univ*of*mich*", false) + ")");
    }

    /**
     * Test of encodeForDN method, of class org.owasp.esapi.Encoder.
     *
     * Additional tests: https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
     */
    public void testEncodeForDN() {
        System.out.println("encodeForDN");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForDN(null));
        assertEquals("No special characters to escape", "Hello", instance.encodeForDN("Hello"));
        assertEquals("No special characters to escape", "Hello \u0007f", instance.encodeForDN("Hello \u0007f"));
        assertEquals("Special characters to escape", "Hello \\c2\\80", instance.encodeForDN("Hello \u0080"));
        assertEquals("Special characters to escape", "Hello \\c3\\bf", instance.encodeForDN("Hello \u00FF"));
        assertEquals("Special characters to escape", "Hello \\df\\bf", instance.encodeForDN("Hello \u07FF"));
        assertEquals("Special characters to escape", "Hello \\e0\\a0\\80", instance.encodeForDN("Hello \u0800"));
        assertEquals("Special characters to escape", "Hello \\e0\\a3\\bf", instance.encodeForLDAP("Hello \u08FF"));
        assertEquals("Special characters to escape", "Hello \\e7\\bf\\bf", instance.encodeForDN("Hello \u7FFF"));
        assertEquals("Special characters to escape", "Hello \\e8\\80\\80", instance.encodeForDN("Hello \u8000"));
        assertEquals("Special characters to escape", "Hello \\e8\\bf\\bf", instance.encodeForDN("Hello \u8FFF"));
        assertEquals("Special characters to escape", "Hello \\ef\\bf\\bf", instance.encodeForDN("Hello \uFFFF"));
        assertEquals("Special characters to escape", "Hello\\ef\\bf\\bd", instance.encodeForDN("Hello�"));
        assertEquals("NUL", "Hi \\00", instance.encodeForDN("Hi \u0000"));
        assertEquals("DQUOTE", "Hi \\\"", instance.encodeForDN("Hi \""));
        assertEquals("PLUS", "Hi \\+", instance.encodeForDN("Hi +"));
        assertEquals("COMMA", "Hi \\,", instance.encodeForDN("Hi ,"));
        assertEquals("SLASH", "Hi \\/", instance.encodeForDN("Hi /"));
        assertEquals("SEMI", "Hi \\;", instance.encodeForDN("Hi ;"));
        assertEquals("LANGLE", "Hi \\<", instance.encodeForDN("Hi <"));
        assertEquals("RANGLE", "Hi \\>", instance.encodeForDN("Hi >"));
        assertEquals("ESC", "Hi \\\\", instance.encodeForDN("Hi \\"));
        assertEquals("leading #", "\\# Hello\\ef\\bf\\bd", instance.encodeForDN("# Hello�"));
        assertEquals("leading space", "\\ Hello\\ef\\bf\\bd", instance.encodeForDN(" Hello�"));
        assertEquals("trailing space", "Hello\\ef\\bf\\bd\\ ", instance.encodeForDN("Hello� "));
        assertEquals("less than greater than", "Hello\\<\\>", instance.encodeForDN("Hello<>"));
        assertEquals("only 3 spaces", "\\  \\ ", instance.encodeForDN("   "));
        assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", instance.encodeForDN(" Hello\\ + , \"World\" ; "));
        assertEquals("Forward slash for \\/Microsoft\\/ \\/AD\\/", instance.encodeForDN("Forward slash for /Microsoft/ /AD/"));
        assertEquals("RFC 4514, Section 4", "CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net",
            "CN=" + instance.encodeForDN("James \"Jim\" Smith, III") + ",DC=" + instance.encodeForDN("example") + ",DC=" + instance.encodeForDN("net"));
    }

    /**
     * Longstanding issue of always lowercasing named HTML entities.  This will be set right now.
     */
    public void testNamedUpperCaseDecoding(){
        System.out.println("namedUpperCaseDecoding");
        String input = "&Uuml;";
        String expected = "Ü";
        assertEquals(expected, ESAPI.encoder().decodeForHTML(input));
    }

    public void testEncodeForXMLNull() {
        System.out.println("encodeFormXMLNull");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForXML(null));
    }

    public void testEncodeForXMLSpace() {
        System.out.println("encodeFormXMLSpace");
        Encoder instance = ESAPI.encoder();
        assertEquals(" ", instance.encodeForXML(" "));
    }

    public void testEncodeForXMLScript() {
        System.out.println("encodeForXMLScript");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#x3c;script&#x3e;", instance.encodeForXML("<script>"));
    }

    public void testEncodeForXMLImmune() {
        System.out.println("encodeForXML");
        Encoder instance = ESAPI.encoder();
        assertEquals(",.-_", instance.encodeForXML(",.-_"));
    }

    public void testEncodeForXMLSymbol() {
        System.out.println("encodeForXMLSymbol");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForXML("!@$%()=+{}[]"));
    }

    public void testEncodeForXMLPound() {
        System.out.println("encodeForXMLPound");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#xa3;", instance.encodeForXML("\u00A3"));
    }

    public void testEncodeForXMLAttributeNull() {
        System.out.println("encodeForXMLAttributeNull");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForXMLAttribute(null));
    }

    public void testEncodeForXMLAttributeSpace() {
        System.out.println("encodeForXMLAttributeSpace");
        Encoder instance = ESAPI.encoder();
        assertEquals(" ", instance.encodeForXMLAttribute(" "));
    }

    public void testEncodeForXMLAttributeScript() {
        System.out.println("encodeForXMLAttributeScript");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#x3c;script&#x3e;", instance.encodeForXMLAttribute("<script>"));
    }

    public void testEncodeForXMLAttributeImmune() {
        System.out.println("encodeFormXMLAttributeImmune");
        Encoder instance = ESAPI.encoder();
        assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
    }

    public void testEncodeForXMLAttributeSymbol() {
        System.out.println("encodeFormXMLAttributeSymbol");
        Encoder instance = ESAPI.encoder();
        assertEquals(" &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
    }

    public void testEncodeForXMLAttributePound() {
        System.out.println("encodeFormXMLAttributePound");
        Encoder instance = ESAPI.encoder();
        assertEquals("&#xa3;", instance.encodeForXMLAttribute("\u00A3"));
    }

    /**
     * Test of encodeForURL method, of class org.owasp.esapi.Encoder.
     *
     * @throws Exception
     */
    public void testEncodeForURL() throws Exception {
        System.out.println("encodeForURL");
        Encoder instance = ESAPI.encoder();
        assertEquals(null, instance.encodeForURL(null));
        assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
    }

    /**
     * Test of decodeFromURL method, of class org.owasp.esapi.Encoder.
     *
     * @throws Exception
     */
    public void testDecodeFromURL() throws Exception {
        System.out.println("decodeFromURL");
        Encoder instance = ESAPI.encoder();
        try {
            assertEquals(null, instance.decodeFromURL(null));
            assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
            assertEquals("     ", instance.decodeFromURL("+++++") );
        } catch ( Exception e ) {
            fail();
        }
        try {
            instance.decodeFromURL( "%3xridiculous" );
            fail();
        } catch( Exception e ) {
            // expected
        }
    }

    /**
     * Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForBase64() {
        System.out.println("encodeForBase64");
        Encoder instance = ESAPI.encoder();

        try {
            assertEquals(null, instance.encodeForBase64(null, false));
            assertEquals(null, instance.encodeForBase64(null, true));
            assertEquals(null, instance.decodeFromBase64(null));
            for ( int i=0; i < 100; i++ ) {
                byte[] r = ESAPI.randomizer().getRandomString( 20, EncoderConstants.CHAR_SPECIALS ).getBytes(PREFERRED_ENCODING);
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
                byte[] r = ESAPI.randomizer().getRandomString( 20, EncoderConstants.CHAR_SPECIALS ).getBytes(PREFERRED_ENCODING);
                String encoded = instance.encodeForBase64( r, ESAPI.randomizer().getRandomBoolean() );
                byte[] decoded = instance.decodeFromBase64( encoded );
                assertTrue( Arrays.equals( r, decoded ) );
            } catch ( IOException e ) {
                fail();
            }
        }
        for ( int i=0; i < 100; i++ ) {
            try {
                byte[] r = ESAPI.randomizer().getRandomString( 20, EncoderConstants.CHAR_SPECIALS ).getBytes(PREFERRED_ENCODING);
                String encoded = ESAPI.randomizer().getRandomString(1, EncoderConstants.CHAR_ALPHANUMERICS) + instance.encodeForBase64( r, ESAPI.randomizer().getRandomBoolean() );
                byte[] decoded = instance.decodeFromBase64( encoded );
                assertFalse( Arrays.equals(r, decoded) );
            } catch( UnsupportedEncodingException ex) {
                fail();
            } catch ( IOException e ) {
                // expected
            }
        }
    }

    /**
     * Test of WindowsCodec
     */
    public void testWindowsCodec() {
        System.out.println("WindowsCodec");
        Encoder instance = ESAPI.encoder();

        Codec<Character> win = new WindowsCodec();
        char[] immune = new char[0];
        assertEquals(null, instance.encodeForOS(win, null));

        PushbackString npbs = new PushbackString("n");
        assertEquals(null, win.decodeCharacter(npbs));

        PushbackString epbs = new PushbackString("");
        assertEquals(null, win.decodeCharacter(epbs));

        Character c = Character.valueOf('<');
        PushbackString cpbs = new PushbackString(win.encodeCharacter(immune, c));
        Character decoded = win.decodeCharacter(cpbs);
        assertEquals(c, decoded);

        String orig = "c:\\jeff";
        String enc = win.encode(EncoderConstants.CHAR_ALPHANUMERICS, orig);
        assertEquals(orig, win.decode(enc));
        assertEquals(orig, win.decode(orig));

        // TODO: Check that these are acceptable for Windows
        assertEquals("c^:^\\jeff", instance.encodeForOS(win, "c:\\jeff"));
        assertEquals("c^:^\\jeff", win.encode(immune, "c:\\jeff"));
        assertEquals("dir^ ^&^ foo", instance.encodeForOS(win, "dir & foo"));
        assertEquals("dir^ ^&^ foo", win.encode(immune, "dir & foo"));
    }

    /**
     * Test of UnixCodec
     */
    public void testUnixCodec() {
        System.out.println("UnixCodec");
        Encoder instance = ESAPI.encoder();

        Codec<Character> unix = new UnixCodec();
        char[] immune = new char[0];
        assertEquals(null, instance.encodeForOS(unix, null));

        PushbackString npbs = new PushbackString("n");
        assertEquals(null, unix.decodeCharacter(npbs));

        Character c = Character.valueOf('<');
        PushbackString cpbs = new PushbackString(unix.encodeCharacter(immune, c));
        Character decoded = unix.decodeCharacter(cpbs);
        assertEquals(c, decoded);

        PushbackString epbs = new PushbackString("");
        assertEquals(null, unix.decodeCharacter(epbs));

        String orig = "/etc/passwd";
        String enc = unix.encode(immune, orig);
        assertEquals(orig, unix.decode(enc));
        assertEquals(orig, unix.decode(orig));

        // TODO: Check that these are acceptable for Unix hosts
        assertEquals("c\\:\\\\jeff", instance.encodeForOS(unix, "c:\\jeff"));
        assertEquals("c\\:\\\\jeff", unix.encode(immune, "c:\\jeff"));
        assertEquals("dir\\ \\&\\ foo", instance.encodeForOS(unix, "dir & foo"));
        assertEquals("dir\\ \\&\\ foo", unix.encode(immune, "dir & foo"));

        // Unix paths (that must be encoded safely)
        // TODO: Check that these are acceptable for Unix
        assertEquals("\\/etc\\/hosts", instance.encodeForOS(unix, "/etc/hosts"));
        assertEquals("\\/etc\\/hosts\\;\\ ls\\ -l", instance.encodeForOS(unix, "/etc/hosts; ls -l"));
    }

    public void testCanonicalizePerformance() throws Exception {
        System.out.println("Canonicalization Performance");
        Encoder encoder = ESAPI.encoder();
        int iterations = 100;
        String normal = "The quick brown fox jumped over the lazy dog";

        long start = System.currentTimeMillis();
        String temp = null;        // Trade in 1/2 doz warnings in Eclipse for one (never read)
        for ( int i=0; i< iterations; i++ ) {
            temp = normal;
        }
        long stop = System.currentTimeMillis();
        System.out.println( "Normal: " + (stop-start) );

        start = System.currentTimeMillis();
        for ( int i=0; i< iterations; i++ ) {
            temp = encoder.canonicalize( normal, false );
        }
        stop = System.currentTimeMillis();
        System.out.println( "Normal Loose: " + (stop-start) );

        start = System.currentTimeMillis();
        for ( int i=0; i< iterations; i++ ) {
            temp = encoder.canonicalize( normal, true );
        }
        stop = System.currentTimeMillis();
        System.out.println( "Normal Strict: " + (stop-start) );

        String attack = "%2&#x35;2%3525&#x32;\\u0036lt;\r\n\r\n%&#x%%%3333\\u0033;&%23101;";

        start = System.currentTimeMillis();
        for ( int i=0; i< iterations; i++ ) {
            temp = attack;
        }
        stop = System.currentTimeMillis();
        System.out.println( "Attack: " + (stop-start) );

        start = System.currentTimeMillis();
        for ( int i=0; i< iterations; i++ ) {
            temp = encoder.canonicalize( attack, false );
        }
        stop = System.currentTimeMillis();
        System.out.println( "Attack Loose: " + (stop-start) );

        start = System.currentTimeMillis();
        for ( int i=0; i< iterations; i++ ) {
            try {
                temp = encoder.canonicalize( attack, true );
            } catch( IntrusionException e ) {
                // expected
            }
        }
        stop = System.currentTimeMillis();
        System.out.println( "Attack Strict: " + (stop-start) );
    }


    public void testConcurrency() {
        System.out.println("Encoder Concurrency");
        for (int i = 0; i < 10; i++) {
            new Thread( new EncoderConcurrencyMock( i )).start();
        }
    }

    /**
     *  A simple class that calls the Encoder to test thread safety
     */
    public class EncoderConcurrencyMock implements Runnable {
        public int num = 0;
        public EncoderConcurrencyMock( int num ) {
            this.num = num;
        }
        public void run() {
            while( true ) {
                String nonce = ESAPI.randomizer().getRandomString( 20, EncoderConstants.CHAR_SPECIALS );
                String result = javaScriptEncode( nonce );
                // randomize the threads
                try {
                    Thread.sleep( ESAPI.randomizer().getRandomInteger( 100, 500 ) );
                } catch (InterruptedException e) {
                    // just continue
                }
                assertTrue( result.equals ( javaScriptEncode( nonce ) ) );
            }
        }

        public String javaScriptEncode(String str) {
            Encoder encoder = DefaultEncoder.getInstance();
            return encoder.encodeForJavaScript(str);
        }
    }

    public void testGetCanonicalizedUri() throws Exception {
        System.out.println("getCanonicalizedUri");
        Encoder e = ESAPI.encoder();

        String expectedUri = "http://palpatine@foo bar.com/path_to/resource?foo=bar#frag";
        //Please note that section 3.2.1 of RFC-3986 explicitly states not to encode
        //password information as in http://palpatine:password@foo.com, and this will
        //not appear in the userinfo field.
        String input = "http://palpatine@foo%20bar.com/path_to/resource?foo=bar#frag";
        URI uri = new URI(input);
        System.out.println(uri.toString());
        assertEquals(expectedUri, e.getCanonicalizedURI(uri));

    }

    public void testGetCanonicalizedUriPiazza() throws Exception {
        System.out.println("getCanonicalizedUriPiazza");
        Encoder e = ESAPI.encoder();

        String expectedUri = "http://127.0.0.1:3000/campaigns?goal=all&section=active&sort-by=-id&status=Draft,Launched";
        //Please note that section 3.2.1 of RFC-3986 explicitly states not to encode
        //password information as in http://palpatine:password@foo.com, and this will
        //not appear in the userinfo field.
        String input = "http://127.0.0.1:3000/campaigns?goal=all&section=active&sort-by=-id&status=Draft%2CLaunched";
        URI uri = new URI(input);
        System.out.println(uri.toString());
        assertEquals(expectedUri, e.getCanonicalizedURI(uri));

    }

    public void testGetCanonicalizedUriWithMailto() throws Exception {
        System.out.println("getCanonicalizedUriWithMailto");
        Encoder e = ESAPI.encoder();

        String expectedUri = "http://palpatine@foo bar.com/path_to/resource?foo=bar#frag";
        //Please note that section 3.2.1 of RFC-3986 explicitly states not to encode
        //password information as in http://palpatine:password@foo.com, and this will
        //not appear in the userinfo field.
        String input = "http://palpatine@foo%20bar.com/path_to/resource?foo=bar#frag";
        URI uri = new URI(input);
        System.out.println(uri.toString());
        assertEquals(expectedUri, e.getCanonicalizedURI(uri));
    }

    public void testHtmlEncodeStrSurrogatePair()
    {
        System.out.println("htmlEncodeStrSurrogatePair");
        Encoder enc = ESAPI.encoder();
        String inStr = new String (new int[]{0x2f804}, 0, 1);
        assertEquals(false, Character.isBmpCodePoint(inStr.codePointAt(0)));
        assertEquals(true, Character.isBmpCodePoint(new String(new int[] {0x0a}, 0, 1).codePointAt(0)));
        String expected = "&#x2f804;";
        String result;

        result = enc.encodeForHTML(inStr);
        assertEquals(expected, result);
    }

    public void testHtmlDecodeHexEntititesSurrogatePair()
    {
        System.out.println("htmlDecodeHexEntitiesSurrogatePair");
        HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
        String expected = new String (new int[]{0x2f804}, 0, 1);
        assertEquals( expected, htmlCodec.decode("&#194564;") );
        assertEquals( expected, htmlCodec.decode("&#x2f804;") );
    }

    public void testUnicodeCanonicalize() {
        System.out.println("UnicodeCanonicalize");
        Encoder e = ESAPI.encoder();
        String input = "测试";
        String expected = "测试";
        String output = e.canonicalize(input);
        assertEquals(expected, output);
    }

    public void testUnicodeCanonicalizePercentEncoding() {
        System.out.println("UnicodeCanonicalizePercentEncoding");
        //TODO:  We need to find a way to specify the encoding type for percent encoding.
        //I believe by default we're doing Latin-1 and we really should be doing UTF-8
        Encoder e = ESAPI.encoder();
        String input = "%E6%B5%8B%E8%AF%95";
        String expected = "测试";
        String output = e.canonicalize(input);
        assertNotSame(expected, output);
    }

    // Test for GitHub Issue 686.
    public void testGetDefaultCanonicalizationCodecs() {
        System.out.println("getDefaultCanonicalizationCodecs");

        // This test input has mixed encoding. It is encoded using %-encoding (e.g.,
        // the %20 representing spaces) and the '\\o' representing backslash
        // encoding. This particular backslash encoding (the "e\\tc") should
        // match *both* JavaScriptCodec and the UnixCodec.
        String testInput = "echo%20\"Hello%20$(id)\";%20echo \"Today is: \\$(date)\" && cat \\.\\.\\///..///..///..//../e\\tc///passwd";

            // SecurityConfiguration before we change it later to tweak the Encoder.DefaultCodecList property
        SecurityConfiguration scOrig = ESAPI.securityConfiguration();

        // We only use the 3 standard (default) Codecs here:
        //      HTMLEntityCodec, PercentCodec, and JavaScriptCodec.
        // Since testInput only has one of these encodings (the PercentCodec),
        // it will not fire off an IntrustionDetectionException here.
        Encoder ecOrig = new DefaultEncoder( scOrig.getDefaultCanonicalizationCodecs() );
        String canonOrig = null;
        boolean caughtExpected = false;
        try {
            ecOrig.canonicalize( testInput );
        } catch( IntrusionException iex) {
            caughtExpected = true;
        }
        assertTrue( caughtExpected );   // Verify it threw an IntrusionException

        // Now set up a case where (via the Encoder.DefaultCodecList property)
        // where "UnixCodec" is added on to the standard list of 3 normal codecs
        // used. Since we also have encoding using '\' encoding that should be
        // recognized by UnixCodec, we should now get an
        // IntrusionException as we have mixed and mulitple encoding
        // both that should be recognized here.
        List<String> myCodecs = new ArrayList<String>();
        myCodecs.add( "HTMLEntityCodec" );
        myCodecs.add( "PercentCodec" );
        // myCodecs.add( "JavaScriptCodec" );   // Don't use this or we will have to parse exception message
                                                // to see if test was successful or not.
            // Instead of JavaScriptCodec, we will use UnixCodec to detect the backslash encoding here.
        myCodecs.add( "UnixCodec" );

            // Finally override ESAPI to use the new SecurityConfiguration
        ESAPI.override( new Conf( ESAPI.securityConfiguration(), myCodecs ) );

        SecurityConfiguration scAltered = ESAPI.securityConfiguration();
        List<String> origCodecs = scOrig.getDefaultCanonicalizationCodecs();
        List<String> alteredCodecs = scAltered.getDefaultCanonicalizationCodecs();

            // First, let's confirm we've actually overridden the SecurityConfiguration.
        assertNotEquals( origCodecs, alteredCodecs );

            // Now do the canonicalization w/ the new list of codecs
        caughtExpected = true;
        try {
            String canonAltered = ESAPI.encoder().canonicalize( testInput );
        } catch( IntrusionException iex ) {
            caughtExpected = true;
        }

        assertTrue( caughtExpected );   // Verify it threw an IntrusionException
    }

    /**
     * Test of encodeForJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJSON_EmptyStrings() {
        System.out.println("testEncodeForJSON_EmptyStrings");
        Encoder instance = ESAPI.encoder();

        // Empty strings
        assertEquals( null, instance.encodeForJSON(null) );
        assertEquals( "", instance.encodeForJSON("") );
        assertEquals( " ", instance.encodeForJSON(" ") );
    }

    /**
     * Test of encodeForJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJSON_7BitClean() {
        System.out.println("testEncodeForJSON_7BitClean");
        Encoder instance = ESAPI.encoder();

        // Walk a message without escaped characters
        String message = "Now is the time for all good men to come to the aide of their country.";
        for ( int i = 1; i < message.length(); ++i ) {
            final String substring = message.substring(0, i);
            assertEquals( substring, instance.encodeForJSON(substring) );
        }
    }

    /**
     * Test of encodeForJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJSON_2CharEscapeSequences() {
        System.out.println("testEncodeForJSON_2CharEscapeSequences");
        Encoder instance = ESAPI.encoder();

        // Two-character sequence escape representations of some
        // popular characters
        assertEquals( "\\b", instance.encodeForJSON("\b") );
        assertEquals( "\\f", instance.encodeForJSON("\f") );
        assertEquals( "\\r", instance.encodeForJSON("\r") );
        assertEquals( "\\n", instance.encodeForJSON("\n") );
        assertEquals( "\\t", instance.encodeForJSON("\t") );
        assertEquals( "\\\"", instance.encodeForJSON("\"") );
        assertEquals( "\\/",  instance.encodeForJSON("/" ) );
        assertEquals( "\\\\", instance.encodeForJSON("\\") );
    }

    /**
     * Test of encodeForJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJSON_ControlCharacters() {
        System.out.println("testEncodeForJSON_ControlCharacters");
        Encoder instance = ESAPI.encoder();

        // All Unicode characters may be placed within the quotation marks,
        // except for the characters that MUST be escaped: quotation mark,
        // reverse solidus, and the control characters (U+0000 through U+001F).
        for ( int i = 0; i <= 0x1f; ++i ) {
            final char ch = (char)i;
            if( ch == '\b' || ch == '\f' || ch == '\r' || ch == '\n' || ch == '\t' ) {
                continue;
            }

            final String str1 = String.format( "\\u%04x", i );
            final String str2 = Character.toString( ch );
            assertEquals( str1, instance.encodeForJSON(str2) );
        }
    }

    /**
     * Test of encodeForJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testEncodeForJSON_PrintableChars() {
        System.out.println("testEncodeForJSON_PrintableChars");
        Encoder instance = ESAPI.encoder();

        // And the remainder of printable characters
        for ( int i = 32; i <= 126; ++i ) {
            final char ch = (char)i;
            if( ch == '/' || ch == '\\' || ch == '\"' ) {
                continue;
            }

            final String str = Character.toString( ch );
            assertEquals( str, instance.encodeForJSON(str) );
        }
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_EmptyStrings() {
        System.out.println("testDecodeFromJSON_EmptyStrings");
        Encoder instance = ESAPI.encoder();

        // Empty strings
        assertEquals( null, instance.decodeFromJSON(null) );
        assertEquals( "", instance.decodeFromJSON("") );
        assertEquals( " ", instance.decodeFromJSON(" ") );
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_7BitClean() {
        System.out.println("testDecodeFromJSON_7BitClean");
        Encoder instance = ESAPI.encoder();

        // Walk a message without escaped characters
        String message = "Now is the time for all good men to come to the aide of their country.";
        for ( int i = 1; i < message.length(); ++i ) {
            final String substring = message.substring(0, i);
            assertEquals( substring, instance.decodeFromJSON(substring) );
        }
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_2CharEscapeSequences() {
        System.out.println("testDecodeFromJSON_2CharEscapeSequences");
        Encoder instance = ESAPI.encoder();

        // Two-character sequence escape representations of some
        // popular characters
        assertEquals( "\b", instance.decodeFromJSON("\\b") );
        assertEquals( "\f", instance.decodeFromJSON("\\f") );
        assertEquals( "\r", instance.decodeFromJSON("\\r") );
        assertEquals( "\n", instance.decodeFromJSON("\\n") );
        assertEquals( "\t", instance.decodeFromJSON("\\t") );
        assertEquals( "\"", instance.decodeFromJSON("\\\"") );
        assertEquals( "/",  instance.decodeFromJSON("\\/" ) );
        assertEquals( "\\", instance.decodeFromJSON("\\\\") );
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_ControlCharacters() {
        System.out.println("testDecodeFromJSON_ControlCharacters");
        Encoder instance = ESAPI.encoder();

        // All Unicode characters may be placed within the quotation marks,
        // except for the characters that MUST be escaped: quotation mark,
        // reverse solidus, and the control characters (U+0000 through U+001F).
        for ( int i = 0; i <= 0x1f; ++i ) {
            final String str = String.format( "\\u%04x", i );
            final Character ch = (char)i;

            assertEquals( Character.toString(ch), instance.decodeFromJSON(str) );
        }
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_PrintableChars() {
        System.out.println("testDecodeFromJSON_PrintableChars");
        Encoder instance = ESAPI.encoder();

        // And the remainder of printable characters
        for ( int i = 32; i <= 126; ++i ) {
            final String str = String.format( "\\u%04x", i );
            final Character ch = (char)i;

            assertEquals( Character.toString(ch), instance.decodeFromJSON(str) );
        }
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_Slashes() {
        System.out.println("testDecodeFromJSON_Slashes");
        Encoder instance = ESAPI.encoder();

        // And a couple extra for good measure...
        assertEquals( "\\", instance.decodeFromJSON("\\u005c") );
        assertEquals( "\\", instance.decodeFromJSON("\\u005C") );
        assertEquals( "\\\\", instance.decodeFromJSON("\\u005c\\u005c") );
        assertEquals( "\\\\", instance.decodeFromJSON("\\u005C\\u005C") );
    }

    /**
     * Test of decodeFromJSON method, of class org.owasp.esapi.Encoder.
     */
    public void testDecodeFromJSON_Malformed() {
        System.out.println("testDecodeFromJSON_Malformed");
        Encoder instance = ESAPI.encoder();

        // Malformed. No '\a' or \c' popular characters
        boolean exceptionThrown = false;
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\a");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. No '\a' or \c' popular characters
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\c");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u0");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u00");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u005");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u0nnnABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u00nnABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. Must have 4 hex digits
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\u005nABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );

        // Malformed. The '\U' must be lowercase
        try {
            exceptionThrown = false;
            String unused = instance.decodeFromJSON("\\U005C");
        }
        catch (IllegalArgumentException e) {
            exceptionThrown = true;
        }
        assertTrue( exceptionThrown );
    }

    /**
     * Test of encodeForJSON and decodeFromJSON methods, of class org.owasp.esapi.Encoder.
     * https://github.com/ESAPI/esapi-java-legacy/pull/722#discussion_r922860329
     */
    public void testRoundtripWithJSON_SupplementaryUnicode () {
        System.out.println("testRoundtripWithJSON_SupplementaryUnicode");
        Encoder instance = ESAPI.encoder();

        // U+1F602 is "\uD83D\uDE02" in Java
        // https://www.fileformat.info/info/unicode/char/1f602/index.htm
        final String FACE_WITH_TEARS_OF_JOY = "\uD83D\uDE02";
        assertEquals( FACE_WITH_TEARS_OF_JOY, instance.decodeFromJSON(instance.encodeForJSON(FACE_WITH_TEARS_OF_JOY)) );
    }

    /**
     * Test of encodeForJSON and decodeFromJSON methods, of class org.owasp.esapi.Encoder.
     */
    public void testRoundtripWithJSON_Random6CharEscapes () {
        System.out.println("testRoundtripWithJSON_Random6CharEscapes");
        Encoder instance = ESAPI.encoder();

        // Walk a message without escaped characters
        final String str1 = "Now is the time for all good men to come to the aide of their country.";

        StringBuilder sb = new StringBuilder();
        Randomizer prng = ESAPI.randomizer();

        for ( int i = 0; i < str1.length(); ++i ) {
            // Perform 6-character escaping on a character with probability 1/4
            final boolean encode = prng.getRandomBoolean() & prng.getRandomBoolean();
            if ( encode ) {
                sb.append( String.format("\\u%04x", (int)str1.charAt(i)) );
            }
            else {
                sb.append( str1.charAt(i) );
            }
        }

        final String str2 = sb.toString();
        assertEquals( str1, instance.decodeFromJSON(str2) );
    }

}
