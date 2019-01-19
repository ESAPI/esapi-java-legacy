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
 *
 */
public class MySQLCodecTest {
    private static final char[] EMPTY_CHAR_ARRAY = new char[0];
    private static  Map<Character, String> ANSI_ESCAPES;
    private static  Map<Character, String> STANDARD_ESCAPES;

    private static final InclusiveRangePair NUMBER_CHAR_RANGE = new InclusiveRangePair(48,57);
    private static final InclusiveRangePair UPPER_CHAR_RANGE = new InclusiveRangePair(65,90);
    private static final InclusiveRangePair LOWER_CHAR_RANGE = new InclusiveRangePair(97,122);

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

    /**
     * ANSI
     * Test showing that for characters up to 256, the only encoded value is the single tick.
     * 
     * when the single tick is encoded, it is updated to be double tick.  All other characters remain unchanged.
     */
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
    /** Upper case letters should not be mutated by the implementation.*/
    @Test
    public void testStandardEncodeUpperCaseRange() {
        performStandardNonEscapeTest(UPPER_CHAR_RANGE);
    }
    /** Lower case letters should not be mutated by the implementation.*/
    @Test
    public void testStandardEncodeLowerCaseRange() {
        performStandardNonEscapeTest(LOWER_CHAR_RANGE);
    }
    /** Numbers should not be mutated by the implementation.*/
    @Test
    public void testStandardEncodeNumbersRange() {
        performStandardNonEscapeTest(NUMBER_CHAR_RANGE);
    }

    /**
     * Helper function for iterating a defined range of values and asserting encoded references are not mutated.
     * @param range {@link InclusiveRangePair} reference to verify
     */
    private void performStandardNonEscapeTest(InclusiveRangePair range) {
        for (int ref = range.getLowerLimit() ; ref <= range.getUpperLimit(); ref ++) {
            char refChar = (char) ref;
            String charAsString = "" + refChar;
            String expected = charAsString;
            String message = String.format("%s (%s) should not be changed when Encoded through the Standard MySQLCodec", charAsString, ref);

            Matcher<String> sameValue = new IsEqual<>(expected);
            errorCollector.checkThat(message, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), sameValue);
        }
    }

    /**
     * Tests that any value under 256 that is not a number, upper case letter, lower case letter, or a special-encoding object is prefixed by a backslash when encoded
     * by a STANDARD MySQLCodec implementation
     */
    @Test
    public void testStandardEncodeNonAlphaNumeric() {
        for (int ref = 0; ref < 256 ; ref ++) {
            char refChar = (char) ref;
            if (NUMBER_CHAR_RANGE.contains(ref) || LOWER_CHAR_RANGE.contains(ref) || UPPER_CHAR_RANGE.contains(ref) || STANDARD_ESCAPES.keySet().contains(refChar)) {
                continue;
            }
            String charAsString = "" + refChar;
            String expected = "\\" + charAsString;
            String message = String.format("%s (%s) should have been escaped when Encoded through the Standard MySQLCodec", charAsString, refChar);

            Matcher<String> sameValue = new IsEqual<>(expected);
            errorCollector.checkThat(message, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), sameValue); 
        }
    }
    
    /**
     * Asserts that predefined specialty escape sequences are provided when encoded.
     */
    @Test
    public void testStandardEncodeEscapeSet() {
        for (Character refChar : STANDARD_ESCAPES.keySet()) {
            String charAsString = "" + refChar;
            String expected = STANDARD_ESCAPES.get(refChar);
            String message = String.format("%s (%s) should have been escaped when Encoded through the Standard MySQLCodec", charAsString, (int) refChar.charValue());

            Matcher<String> sameValue = new IsEqual<>(expected);
            errorCollector.checkThat(message, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), sameValue);    
        }
    }


    private static class InclusiveRangePair {
        private final int upperInclusive;
        private final int lowerInclusive;

        public InclusiveRangePair (int minValueAllowed,int maxValueAllowed) {
            upperInclusive = maxValueAllowed;
            lowerInclusive = minValueAllowed;
        }

        public boolean contains (int value) {
            return value >= lowerInclusive && value <= upperInclusive;
        }

        public int getUpperLimit() {
            return upperInclusive;
        }

        public int getLowerLimit() {
            return lowerInclusive;
        }
    }
}
