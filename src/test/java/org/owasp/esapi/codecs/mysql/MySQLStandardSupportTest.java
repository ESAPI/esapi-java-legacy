package org.owasp.esapi.codecs.mysql;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.Matcher;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.IsNull;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.owasp.esapi.codecs.PushbackSequence;
import org.owasp.esapi.codecs.PushbackString;
/**
 * Tests to show {@link MySQLCodec} with {@link Mode#ANSI}
 * comply with the OWASP Escaping recommendations
 * 
 * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping
 *
 */
public class MySQLStandardSupportTest {
    private static  Map<Character, String> STANDARD_ESCAPES;

    private static final InclusiveRangePair NUMBER_CHAR_RANGE = new InclusiveRangePair(48,57);
    private static final InclusiveRangePair UPPER_CHAR_RANGE = new InclusiveRangePair(65,90);
    private static final InclusiveRangePair LOWER_CHAR_RANGE = new InclusiveRangePair(97,122);

    @Rule
    public ErrorCollector errorCollector = new ErrorCollector();
    
    /** Unit IN Test.*/
    private MySQLStandardSupport uit;
    
    private MySQLCodec codecSpy;

    @BeforeClass
    public static void createCodecEscapeMaps () {
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

        STANDARD_ESCAPES = escapesStd;
    }
    
    @Before
    public void setup() {
        codecSpy = new MySQLCodec(MySQLMode.STANDARD);
        codecSpy = Mockito.spy(codecSpy);
        uit = new MySQLStandardSupport(codecSpy);
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
            String encodeMsg = String.format("%s (%s) should not be changed when Encoded through the Standard MySQLCodec", charAsString, ref);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the Standard MySQLCodec", charAsString, ref, expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<Character> decodeExpect = new IsNull<>();
            errorCollector.checkThat(encodeMsg, uit.encodeCharacter(refChar), encodeExpect);
            errorCollector.checkThat(decodeMsg, uit.decodeCharacter(new PushbackString(expected)), decodeExpect);
            Mockito.verify(codecSpy, Mockito.times(1)).getHexForNonAlphanumeric(refChar);
            Mockito.reset(codecSpy);
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
            String encodeMsg = String.format("%s (%s) should have been escaped when Encoded through the Standard MySQLCodec", charAsString, refChar);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the Standard MySQLCodec", charAsString, ref, expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<Character> decodeExpect = new IsEqual<>(refChar);
            errorCollector.checkThat(encodeMsg, uit.encodeCharacter(refChar), encodeExpect);
            errorCollector.checkThat(decodeMsg, uit.decodeCharacter(new PushbackString(expected)), decodeExpect);
            Mockito.verify(codecSpy, Mockito.times(1)).getHexForNonAlphanumeric(refChar);
            Mockito.reset(codecSpy);
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
            String encodeMsg = String.format("%s (%s) should have been escaped when Encoded through the Standard MySQLCodec", charAsString, (int) refChar.charValue());
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the Standard MySQLCodec", charAsString, (int) refChar.charValue(), expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<Character> decodeExpect = new IsEqual<>(refChar);
            errorCollector.checkThat(encodeMsg, uit.encodeCharacter(refChar), encodeExpect);
            errorCollector.checkThat(decodeMsg, uit.decodeCharacter(new PushbackString(expected)), decodeExpect);
            Mockito.verify(codecSpy, Mockito.times(1)).getHexForNonAlphanumeric(refChar);
            Mockito.reset(codecSpy);
        }
    }
    
    /**
     * If the first character is null, null is expected
     */
    @Test
    public void testStandardDecodePushbackSequenceNullFirstElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn(null);
        
        Character decChar = uit.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(1)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    /**
     * If the first character is a backslash, and the second character is null, null is expected
     */
    @Test
    public void testStandardDecodePushbackSequenceNullSecondElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn('\\').thenReturn(null);
        
        Character decChar = uit.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(2)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
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
