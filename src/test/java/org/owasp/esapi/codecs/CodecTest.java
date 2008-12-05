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
public class CodecTest extends TestCase {

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
    public CodecTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     */
    protected void setUp() throws Exception {
        // none
    }

    /**
     * {@inheritDoc}
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
        TestSuite suite = new TestSuite(CodecTest.class);
        return suite;
    }

	public void testEncode() {
        System.out.println("encode");

        // htmlCodec
        assertEquals( "&#116;&#101;&#115;&#116;", htmlCodec.encode("test") );
        
        // percentCodec
        assertEquals( "%3c", percentCodec.encode("<") );

        // javaScriptCodec
        assertEquals( "\\x3C", javaScriptCodec.encode("<") );
        
        // vbScriptCodec
        assertEquals( "\"<", vbScriptCodec.encode("<") );

        // cssCodec
        assertEquals( "\\<", cssCodec.encode("<") );

        // mySQLCodecANSI
        assertEquals( "\'\'", mySQLCodecANSI.encode("\'") );

        // mySQLCodecStandard
        assertEquals( "\\<", mySQLCodecStandard.encode("<") );

        // oracleCodec
        assertEquals( "\\<", oracleCodec.encode("<") );

        // unixCodec
        assertEquals( "\\<", unixCodec.encode("<") );

        // windowsCodec
        assertEquals( "^<", windowsCodec.encode("<") );
	}
	
	public void testEncodeCharacter() {
        System.out.println("encodeCharacter");
        Character c = new Character('<');

        // htmlCodec
        assertEquals( "&lt;", htmlCodec.encodeCharacter(c) );

        // percentCodec
        assertEquals( "%3c", percentCodec.encodeCharacter(c) );

        // javaScriptCodec
        assertEquals( "\\x3C", javaScriptCodec.encodeCharacter(c) );
        
        // vbScriptCodec
        assertEquals( "\"<", vbScriptCodec.encodeCharacter(c) );

        // cssCodec
        assertEquals( "\\<", cssCodec.encodeCharacter(c) );

        // mySQLCodecANSI
        assertEquals( "\'\'", mySQLCodecANSI.encodeCharacter(new Character('\'')) );

        // mySQLCodecStandard
        assertEquals( "\\<", mySQLCodecStandard.encodeCharacter(c) );

        // oracleCodec
        assertEquals( "\\<", oracleCodec.encodeCharacter(c) );

        // unixCodec
        assertEquals( "\\<", unixCodec.encodeCharacter(c) );

        // windowsCodec
        assertEquals( "^<", windowsCodec.encodeCharacter(c) );
	}
	
	public void testDecode() {
        System.out.println("decode");
        
        // htmlCodec
        assertEquals( "test!", htmlCodec.decode("&#116;&#101;&#115;&#116;!") );
        assertEquals( "test!", htmlCodec.decode("&#x74;&#x65;&#x73;&#x74;!") );
        assertEquals( "&jeff;", htmlCodec.decode("&jeff;") );

        // percentCodec
        assertEquals( "<", percentCodec.decode("%3c") );

        // javaScriptCodec
        assertEquals( "<", javaScriptCodec.decode("\\x3c") );
        
        // vbScriptCodec
        assertEquals( "<", vbScriptCodec.decode("\"<") );

        // cssCodec
        assertEquals( "<", cssCodec.decode("\\<") );

        // mySQLCodecANSI
        assertEquals( "\'", mySQLCodecANSI.decode("\'\'") );

        // mySQLCodecStandard
        assertEquals( "<", mySQLCodecStandard.decode("\\<") );

        // oracleCodec
        assertEquals( "<", oracleCodec.decode("\\<") );

        // unixCodec
        assertEquals( "<", unixCodec.decode("\\<") );

        // windowsCodec
        assertEquals( "<", windowsCodec.decode("^<") );
	}
	
	
	public void testDecodeCharacter() {
        System.out.println("decodeCharacter");
        Character c = new Character('<');

        // htmlCodec
        assertEquals( c, htmlCodec.decodeCharacter(new PushbackString("&lt;")) );

        // percentCodec
        assertEquals( c, percentCodec.decodeCharacter(new PushbackString("%3c") ));

        // javaScriptCodec
        assertEquals( c, javaScriptCodec.decodeCharacter(new PushbackString("\\x3c") ));
        
        // vbScriptCodec
        assertEquals( c, vbScriptCodec.decodeCharacter(new PushbackString("\"<") ));

        // cssCodec
        assertEquals( c, cssCodec.decodeCharacter(new PushbackString("\\3c") ));

        // mySQLCodecANSI
        assertEquals( new Character('\''), mySQLCodecANSI.decodeCharacter(new PushbackString("\'\'") ));

        // mySQLCodecStandard
        assertEquals( c, mySQLCodecStandard.decodeCharacter(new PushbackString("\\<") ));

        // oracleCodec
        assertEquals( c, oracleCodec.decodeCharacter(new PushbackString("\\<") ));

        // unixCodec
        assertEquals( c, unixCodec.decodeCharacter(new PushbackString("\\<") ));

        // windowsCodec
        assertEquals( c, windowsCodec.decodeCharacter(new PushbackString("^<") ));
	}
	
}