package org.owasp.esapi.codecs;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.Matcher;
import org.hamcrest.core.IsEqual;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
/**
 * Tests to show {@link MySQLCodec} with {@link Mode#ANSI}
 * comply with the OWASP Escaping recommendations
 * 
 * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping
 * @author Jeremiah
 *
 */
public class MySQLCodecTest {
    private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    private static  Map<Character, String> ANSI_ESCAPES;
    private static  Map<Character, String> STANDARD_ESCAPES;

    private MySQLCodec uitAnsi = new MySQLCodec(Mode.ANSI);
    private MySQLCodec uitMySqlStandard = new MySQLCodec(Mode.STANDARD);
    
    
    @Rule
    public ErrorCollector errorCollector = new ErrorCollector();
   

    @BeforeClass
    public static void createStandardCodecEscapes () {
        Map<Character, String> escapesStd = new HashMap<>();
        escapesStd.put( (char)0x00,  "\\0");
        escapesStd.put( (char)0x08,  "\\b");
        escapesStd.put( (char)0x09,  "\\t");
        escapesStd.put( (char)0x0a,  "\\n");
        escapesStd.put( (char)0x0d,  "\\r");
        escapesStd.put( (char)0x1a,  "\\Z");
        escapesStd.put( (char)0x22,  "\\\"");
        escapesStd.put( (char)0x25,  "\\%");
        escapesStd.put( (char)0x27,  "\\'");
        escapesStd.put( (char)0x5c,  "\\\\");
        escapesStd.put( (char)0x5f,  "\\_");
        
        Map<Character, String> escapesAnsi = new HashMap<>();
        escapesAnsi.put( '\'',  "\'\'");
        
        STANDARD_ESCAPES = escapesStd;
        ANSI_ESCAPES = escapesAnsi;
    }
    
    @Test
    public void testAnsiEncodeTo256() {
        for (int ref = 0 ; ref < 256; ref ++) {
             char refChar = (char) ref;
             boolean shouldEscape = ANSI_ESCAPES.containsKey(refChar);
            
             
             String charAsString = "" + refChar;
             String expected = charAsString;
             String message = String.format("%s (%s) should not be altered when Encoded through the ANSI MySQLCodec", charAsString, ref);
             if (shouldEscape) {
                 expected = ANSI_ESCAPES.get(refChar);
                 message = String.format("%s (%s) should have been escaped when Encoded through the ANSI MySQLCodec", charAsString, ref);
             }
               
                Matcher<String> sameValue = new IsEqual<>(expected);
              errorCollector.checkThat(message, uitAnsi.encode(EMPTY_CHAR_ARRAY, charAsString), sameValue);   
        }
    }
    
    @Test
    public void testStandardEncodeTo256() {
        for (int ref = 0 ; ref < 256; ref ++) {
             char refChar = (char) ref;
             boolean shouldEscape = STANDARD_ESCAPES.containsKey(refChar);
            
             
             String charAsString = "" + refChar;
             String expected = "\\" + charAsString;
             String message = String.format("%s (%s) should not be altered when Encoded through the Standard MySQLCodec", charAsString, ref);
             if (shouldEscape) {
                 expected = STANDARD_ESCAPES.get(refChar);
                 message = String.format("%s (%s) should have been escaped when Encoded through the Standard MySQLCodec", charAsString, ref);
             }
               
                Matcher<String> sameValue = new IsEqual<>(expected);
              errorCollector.checkThat(message, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), sameValue);   
        }
    }
 

}
