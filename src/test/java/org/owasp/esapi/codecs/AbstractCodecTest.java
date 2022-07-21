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
package org.owasp.esapi.codecs;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;



/**
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class AbstractCodecTest extends TestCase {

    private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    private static final Character LESS_THAN = Character.valueOf('<');
    private static final Character SINGLE_QUOTE = Character.valueOf('\'');
    private HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
    private PercentCodec percentCodec = new PercentCodec();
    private JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
    private VBScriptCodec vbScriptCodec = new VBScriptCodec();
    private CSSCodec cssCodec = new CSSCodec();
    private MySQLCodec mySQLCodecANSI = new MySQLCodec( MySQLCodec.ANSI_MODE );
    private MySQLCodec mySQLCodecStandard = new MySQLCodec( MySQLCodec.MYSQL_MODE );
    private OracleCodec oracleCodec = new OracleCodec();
    private UnixCodec unixCodec = new UnixCodec();
    private WindowsCodec windowsCodec = new WindowsCodec();

    /**
     * Instantiates a new access reference map test.
     *
     * @param testName
     *            the test name
     */
    public AbstractCodecTest(String testName) {
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
     * {@inheritDoc}
     * @throws Exception
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
        TestSuite suite = new TestSuite(AbstractCodecTest.class);
        return suite;
    }

    public void testHtmlEncode()
    {
            assertEquals( "test", htmlCodec.encode( EMPTY_CHAR_ARRAY, "test") );
    }

    public void testPercentEncode()
    {
            assertEquals( "%3C", percentCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }


    public void testJavaScriptEncode()
    {
            assertEquals( "\\x3C", javaScriptCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }

    public void testVBScriptEncode()
    {
            assertEquals( "chrw(60)", vbScriptCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }

    public void testCSSEncode()
    {
            assertEquals( "\\3c ", cssCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }

    public void testCSSInvalidCodepointDecode()
    {
        assertEquals("\uFFFDg", cssCodec.decode("\\abcdefg") );
    }

    public void testMySQLANSCIEncode()
    {
            assertEquals( "\'\'", mySQLCodecANSI.encode(EMPTY_CHAR_ARRAY, "\'") );
    }

    public void testMySQLStandardEncode()
    {
            assertEquals( "\\<", mySQLCodecStandard.encode(EMPTY_CHAR_ARRAY, "<") );
    }

    public void testOracleEncode()
    {
            assertEquals( "\'\'", oracleCodec.encode(EMPTY_CHAR_ARRAY, "\'") );
    }

    public void testUnixEncode()
    {
            assertEquals( "\\<", unixCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }

    public void testWindowsEncode()
    {
            assertEquals( "^<", windowsCodec.encode(EMPTY_CHAR_ARRAY, "<") );
    }


    public void testHtmlEncodeChar()
    {

            assertEquals( "&lt;", htmlCodec.encodeCharacter(EMPTY_CHAR_ARRAY, (int) LESS_THAN) );
    }

    public void testHtmlEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "&#x100;";
        String result;
        //The new default for HTMLEntityCodec is ints/Integers.  Use Character/char at your own risk!
        //Characters destroy non-BMP codepoints.  This Codec is now supposed surpass that.
        result = htmlCodec.encodeCharacter(EMPTY_CHAR_ARRAY, (int) in);
        // this should be escaped
        assertFalse(inStr.equals(result));
        // UTF-8 encoded and then percent escaped
        assertEquals(expected, result);
    }

    public void testHtmlEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "&#x100;";
        String result;

            result = htmlCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
        // UTF-8 encoded and then percent escaped
            assertEquals(expected, result);
    }

    public void testPercentEncodeChar()
    {
            assertEquals( "%3C", percentCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testPercentEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "%C4%80";
        String result;

            result = percentCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
        // UTF-8 encoded and then percent escaped
            assertEquals(expected, result);
    }

    public void testPercentEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "%C4%80";
        String result;

            result = percentCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
        // UTF-8 encoded and then percent escaped
            assertEquals(expected, result);
    }

    public void testJavaScriptEncodeChar()
    {
            assertEquals( "\\x3C", javaScriptCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testJavaScriptEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\u0100";
        String result;

            result = javaScriptCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testJavaScriptEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\u0100";
        String result;

            result = javaScriptCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testVBScriptEncodeChar()
    {
            assertEquals( "chrw(60)", vbScriptCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testVBScriptEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        // FIXME I don't know vb...
        // String expected = "\\u0100";
        String result;

            result = vbScriptCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            //assertEquals(expected,result);
    }

    public void testVBScriptEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        // FIXME I don't know vb...
        // String expected = "chrw(0x100)";
        String result;

            result = vbScriptCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            // assertEquals(expected,result);
    }

    public void testCSSEncodeChar()
    {
            assertEquals( "\\3c ", cssCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testCSSEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\100 ";
        String result;

            result = cssCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testCSSEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\100 ";
        String result;

            result = cssCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testMySQLANSIEncodeChar()
    {
            assertEquals( "\'\'", mySQLCodecANSI.encodeCharacter(EMPTY_CHAR_ARRAY, SINGLE_QUOTE));
    }

    public void testMySQLStandardEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

            result = mySQLCodecStandard.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testMySQLStandardEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

            result = mySQLCodecStandard.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testMySQLStandardEncodeChar()
    {
            assertEquals( "\\<", mySQLCodecStandard.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testOracleEncodeChar()
    {
            assertEquals( "\'\'", oracleCodec.encodeCharacter(EMPTY_CHAR_ARRAY, SINGLE_QUOTE) );
    }

    public void testUnixEncodeChar()
    {
            assertEquals( "\\<", unixCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testUnixEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

            result = unixCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testUnixEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "\\" + in;
        String result;

            result = unixCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testWindowsEncodeChar()
    {
            assertEquals( "^<", windowsCodec.encodeCharacter(EMPTY_CHAR_ARRAY, LESS_THAN) );
    }

    public void testWindowsEncodeChar0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "^" + in;
        String result;

            result = windowsCodec.encodeCharacter(EMPTY_CHAR_ARRAY, in);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testWindowsEncodeStr0x100()
    {
        Character in = 0x100;
        String inStr = Character.toString(in);
        String expected = "^" + in;
        String result;

            result = windowsCodec.encode(EMPTY_CHAR_ARRAY, inStr);
        // this should be escaped
            assertFalse(inStr.equals(result));
            assertEquals(expected,result);
    }

    public void testHtmlDecodeDecimalEntities()
    {
            assertEquals( "test!", htmlCodec.decode("&#116;&#101;&#115;&#116;!") );
    }

    public void testHtmlDecodeHexEntitites()
    {
            assertEquals( "test!", htmlCodec.decode("&#x74;&#x65;&#x73;&#x74;!") );
    }

    public void testHtmlDecodeInvalidAttribute()
    {
            assertEquals( "&jeff;", htmlCodec.decode("&jeff;") );
    }

    public void testHtmlDecodeAmp()
    {
        assertEquals("&", htmlCodec.decode("&amp;"));
        assertEquals("&X", htmlCodec.decode("&amp;X"));
        assertEquals("&", htmlCodec.decode("&amp"));
        assertEquals("&X", htmlCodec.decode("&ampX"));
    }

    public void testHtmlDecodeLt()
    {
        assertEquals("<", htmlCodec.decode("&lt;"));
        assertEquals("<X", htmlCodec.decode("&lt;X"));
        assertEquals("<", htmlCodec.decode("&lt"));
        assertEquals("<X", htmlCodec.decode("&ltX"));
    }

    public void testHtmlDecodeSup1()
    {
        assertEquals("\u00B9", htmlCodec.decode("&sup1;"));
        assertEquals("\u00B9X", htmlCodec.decode("&sup1;X"));
        assertEquals("\u00B9", htmlCodec.decode("&sup1"));
        assertEquals("\u00B9X", htmlCodec.decode("&sup1X"));
    }

    public void testHtmlDecodeSup2()
    {
        assertEquals("\u00B2", htmlCodec.decode("&sup2;"));
        assertEquals("\u00B2X", htmlCodec.decode("&sup2;X"));
        assertEquals("\u00B2", htmlCodec.decode("&sup2"));
        assertEquals("\u00B2X", htmlCodec.decode("&sup2X"));
    }

    public void testHtmlDecodeSup3()
    {
        assertEquals("\u00B3", htmlCodec.decode("&sup3;"));
        assertEquals("\u00B3X", htmlCodec.decode("&sup3;X"));
        assertEquals("\u00B3", htmlCodec.decode("&sup3"));
        assertEquals("\u00B3X", htmlCodec.decode("&sup3X"));
    }

    public void testHtmlDecodeSup()
    {
        assertEquals("\u2283", htmlCodec.decode("&sup;"));
        assertEquals("\u2283X", htmlCodec.decode("&sup;X"));
        assertEquals("\u2283", htmlCodec.decode("&sup"));
        assertEquals("\u2283X", htmlCodec.decode("&supX"));
    }

    public void testHtmlDecodeSupe()
    {
        assertEquals("\u2287", htmlCodec.decode("&supe;"));
        assertEquals("\u2287X", htmlCodec.decode("&supe;X"));
        assertEquals("\u2287", htmlCodec.decode("&supe"));
        assertEquals("\u2287X", htmlCodec.decode("&supeX"));
    }

    public void testHtmlDecodePi()
    {
        assertEquals("\u03C0", htmlCodec.decode("&pi;"));
        assertEquals("\u03C0X", htmlCodec.decode("&pi;X"));
        assertEquals("\u03C0", htmlCodec.decode("&pi"));
        assertEquals("\u03C0X", htmlCodec.decode("&piX"));
    }

    public void testHtmlDecodePiv()
    {
        assertEquals("\u03D6", htmlCodec.decode("&piv;"));
        assertEquals("\u03D6X", htmlCodec.decode("&piv;X"));
        assertEquals("\u03D6", htmlCodec.decode("&piv"));
        assertEquals("\u03D6X", htmlCodec.decode("&pivX"));
    }

    public void testHtmlDecodeTheta()
    {
        assertEquals("\u03B8", htmlCodec.decode("&theta;"));
        assertEquals("\u03B8X", htmlCodec.decode("&theta;X"));
        assertEquals("\u03B8", htmlCodec.decode("&theta"));
        assertEquals("\u03B8X", htmlCodec.decode("&thetaX"));
    }

    public void testHtmlDecodeThetasym()
    {
        assertEquals("\u03D1", htmlCodec.decode("&thetasym;"));
        assertEquals("\u03D1X", htmlCodec.decode("&thetasym;X"));
        assertEquals("\u03D1", htmlCodec.decode("&thetasym"));
        assertEquals("\u03D1X", htmlCodec.decode("&thetasymX"));
    }

    public void testPercentDecode()
    {
            assertEquals( "<", percentCodec.decode("%3c") );
    }

    public void testJavaScriptDecodeBackSlashHex()
    {
            assertEquals( "<", javaScriptCodec.decode("\\x3c") );
    }

    public void testVBScriptDecode()
    {
            assertEquals( "<", vbScriptCodec.decode("\"<") );
    }

    public void testCSSDecode()
    {
            assertEquals("<", cssCodec.decode("\\<") );
    }

    public void testCSSDecodeHexNoSpace()
    {
            assertEquals("Axyz", cssCodec.decode("\\41xyz") );
    }

    public void testCSSDecodeZeroHexNoSpace()
    {
            assertEquals("Aabc", cssCodec.decode("\\000041abc") );
    }

    public void testCSSDecodeHexSpace()
    {
            assertEquals("Aabc", cssCodec.decode("\\41 abc") );
    }

    public void testCSSDecodeNL()
    {
            assertEquals("abcxyz", cssCodec.decode("abc\\\nxyz") );
    }

    public void testCSSDecodeCRNL()
    {
            assertEquals("abcxyz", cssCodec.decode("abc\\\r\nxyz") );
    }

    public void testMySQLANSIDecode()
    {
            assertEquals( "\'", mySQLCodecANSI.decode("\'\'") );
    }

    public void testMySQLStandardDecode()
    {
            assertEquals( "<", mySQLCodecStandard.decode("\\<") );
    }

    public void testOracleDecode()
    {
            assertEquals( "\'", oracleCodec.decode("\'\'") );
    }

    public void testUnixDecode()
    {
            assertEquals( "<", unixCodec.decode("\\<") );
    }

        public void testWindowsDecode()
    {
            assertEquals( "<", windowsCodec.decode("^<") );
    }

    public void testHtmlDecodeCharLessThan()
    {
        Integer value = htmlCodec.decodeCharacter(new PushBackSequenceImpl("&lt;"));
        assertEquals(new Integer(60), value);
        StringBuilder sb = new StringBuilder().appendCodePoint(value);
        assertEquals( LESS_THAN.toString(), sb.toString());
    }

    public void testPercentDecodeChar()
    {
            assertEquals( LESS_THAN, percentCodec.decodeCharacter(new PushbackString("%3c") ));
    }

        public void testJavaScriptDecodeCharBackSlashHex()
    {
            assertEquals( LESS_THAN, javaScriptCodec.decodeCharacter(new PushbackString("\\x3c") ));
    }

    public void testVBScriptDecodeChar()
    {
            assertEquals( LESS_THAN, vbScriptCodec.decodeCharacter(new PushbackString("\"<") ));
    }

    public void testCSSDecodeCharBackSlashHex()
    {
            assertEquals( LESS_THAN, cssCodec.decodeCharacter(new PushbackString("\\3c") ));
    }

    public void testMySQLANSIDecodCharQuoteQuote()
    {
            assertEquals( SINGLE_QUOTE, mySQLCodecANSI.decodeCharacter(new PushbackString("\'\'") ));
    }

        public void testMySQLStandardDecodeCharBackSlashLessThan()
    {
            assertEquals( LESS_THAN, mySQLCodecStandard.decodeCharacter(new PushbackString("\\<") ));
    }

    public void testOracleDecodeCharBackSlashLessThan()
    {
            assertEquals( SINGLE_QUOTE, oracleCodec.decodeCharacter(new PushbackString("\'\'") ));
    }

        public void testUnixDecodeCharBackSlashLessThan()
    {
            assertEquals( LESS_THAN, unixCodec.decodeCharacter(new PushbackString("\\<") ));
    }

        public void testWindowsDecodeCharCarrotLessThan()
    {
            assertEquals( LESS_THAN, windowsCodec.decodeCharacter(new PushbackString("^<") ));
    }
}
