package org.owasp.esapi.codecs;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.Matcher;
import org.hamcrest.core.IsEqual;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.powermock.reflect.Whitebox;
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
    @Rule
    public ExpectedException exEx = ExpectedException.none();


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
            String encodeMsg = String.format("%s (%s) should not be altered when Encoded through the ANSI MySQLCodec", charAsString, ref);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when DECODED through the ANSI MySQLCodec", charAsString, ref, expected);
            if (shouldEscape) {
                expected = ANSI_ESCAPES.get(refChar);
                encodeMsg = String.format("%s (%s) should have been escaped when Encoded through the ANSI MySQLCodec", charAsString, ref);
            }
            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitAnsi.encode(EMPTY_CHAR_ARRAY, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitAnsi.decode(expected), decodeExpect);
        }
    }
    @Test
    public void testAnsiEncodeWithImmuneSet() {
        //The only value that is encoded is single tick. The immunity list does not impact normal capability in ANSI mode
        char[] immuneChars = new char[] {15, 91,150, 255};
        
        for (char refChar : immuneChars) {
            int ref = refChar;
            String charAsString = "" + refChar;
            String expected =  charAsString;
            String encodeMsg = String.format("%s (%s) should not be escaped when in the immunity list provided to Encoded through the ANSI MySQLCodec", charAsString, refChar);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the ANSI MySQLCodec", charAsString, ref, expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitAnsi.encode(immuneChars, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitAnsi.decode(expected), decodeExpect);
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
            String encodeMsg = String.format("%s (%s) should not be changed when Encoded through the Standard MySQLCodec", charAsString, ref);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the Standard MySQLCodec", charAsString, ref, expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitMySqlStandard.decode(expected), decodeExpect);
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
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitMySqlStandard.decode(expected), decodeExpect);

        }
    }
    
    @Test
    public void testStandardEncodeWithImmuneSet() {
        //These values normally fall under the encodeNonAlphaNumeric test content.
        char[] immuneChars = new char[] {15, 91,150, 255};
        
        for (char refChar : immuneChars) {
            int ref = refChar;
            String charAsString = "" + refChar;
          //Typically, we should expect the encode to be the original value prefixed by two backslashes.
            String expected =  charAsString;
            String encodeMsg = String.format("%s (%s) should not be escaped when in the immunity list provided to Encoded through the Standard MySQLCodec", charAsString, refChar);
            String decodeMsg = String.format("%s (%s) [%s] should match original value when Encoded through the Standard MySQLCodec", charAsString, ref, expected);

            Matcher<String> encodeExpect = new IsEqual<>(expected);
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitMySqlStandard.encode(immuneChars, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitMySqlStandard.decode(expected), decodeExpect);
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
            Matcher<String> decodeExpect = new IsEqual<>(charAsString);
            errorCollector.checkThat(encodeMsg, uitMySqlStandard.encode(EMPTY_CHAR_ARRAY, charAsString), encodeExpect);
            errorCollector.checkThat(decodeMsg, uitMySqlStandard.decode(expected), decodeExpect);   
        }
    }

    /**
     * If the first element in the {@link PushbackSequence} is null, then null is expected.
     */
    @Test
    public void testAnsiDecodePushbackSequenceNullFirstElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn(null);
        
        Character decChar = uitAnsi.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(1)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    
    /**
     * If the first character is a single tick, and the second character is null, null is expected
     */
    @Test
    public void testAnsiDecodePushbackSequenceNullSecondElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn('\'').thenReturn(null);
        
        Character decChar = uitAnsi.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(2)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    
    /**
     * If the first character is a single tick and the second character is NOT a single tick (escaped tick), then null is expected.
     */
    @Test
    public void testAnsiDecodePushbackSequenceNonTickSecondElmentReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn('\'').thenReturn('A');
        
        Character decChar = uitAnsi.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(2)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    /**
     * If two single ticks are read in sequence, a single tick is expected.
     */
    @Test
    public void testAnsiDecodePushbackSequenceReturnsSingleTick() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn('\'').thenReturn('\'');
        
        Character decChar = uitAnsi.decodeCharacter(mockPushback);
        Assert.assertEquals('\'', decChar.charValue());
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(2)).next();
        Mockito.verify(mockPushback, Mockito.times(0)).reset();
        
    }

    /**
     * If the first character is not a single tick, null is returned.
     */
    @Test
    public void testAnsiDecodePushbackSequenceNonTickFirstElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn('A');
        
        Character decChar = uitAnsi.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(1)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    
    /**
     * If the first character is null, null is expected
     */
    @Test
    public void testStandardDecodePushbackSequenceNullFirstElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn(null);
        
        Character decChar = uitMySqlStandard.decodeCharacter(mockPushback);
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
        
        Character decChar = uitMySqlStandard.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(2)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
    
    @Test
    public void testCreateAnsiByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLCodec.ANSI_MODE);
        Object configMode = Whitebox.getInternalState(codec, "mode");
        Assert.assertEquals(Mode.ANSI, configMode);
    }
    
    @Test
    public void testCreateStandardByInt() {
        MySQLCodec codec = new MySQLCodec(MySQLCodec.MYSQL_MODE);
        Object configMode = Whitebox.getInternalState(codec, "mode");
        Assert.assertEquals(Mode.STANDARD, configMode);
    }
    
    @Test
    public void testCreateUnsupportedModeByInt() {
        exEx.expect(IllegalArgumentException.class);
        String message = String.format("No Mode for %s. Valid references are MySQLStandard: %s or ANSI: %s", Integer.MIN_VALUE, MySQLCodec.MYSQL_MODE, MySQLCodec.ANSI_MODE);
        exEx.expectMessage(message);
        new MySQLCodec(Integer.MIN_VALUE);
       
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
