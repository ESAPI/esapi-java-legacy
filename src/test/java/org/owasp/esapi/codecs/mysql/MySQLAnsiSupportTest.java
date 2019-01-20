package org.owasp.esapi.codecs.mysql;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.Matcher;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.IsNull;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.owasp.esapi.codecs.PushbackSequence;
import org.owasp.esapi.codecs.PushbackString;
/**

 * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping
 *
 */
public class MySQLAnsiSupportTest {
    private static  Map<Character, String> ANSI_ESCAPES;

    @Rule
    public ErrorCollector errorCollector = new ErrorCollector();

    private MySQLAnsiSupport uit = new MySQLAnsiSupport();

    @BeforeClass
    public static void createCodecEscapeMaps () {
        Map<Character, String> escapesAnsi = new HashMap<>();
        escapesAnsi.put( '\'',  "\'\'");

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
            String encodeMsg = String.format("%s (%s) should not be altered when Encoded", charAsString, ref);
            String decodeMsg =  String.format("%s (%s) [%s] be null DECODED", charAsString, ref, expected);
            Matcher<Character> decodeExpect =  new IsNull<Character>();
            if (shouldEscape) {
                expected = ANSI_ESCAPES.get(refChar);
                encodeMsg = String.format("%s (%s) should have been escaped when Encoded", charAsString, ref);
                decodeMsg =  String.format("%s (%s) [%s] should match original value when DECODED", charAsString, ref, expected);
                decodeExpect =  new IsEqual<Character>(refChar);
            }
            Matcher<String> encodeExpect = new IsEqual<>(expected);
            errorCollector.checkThat(encodeMsg, uit.encodeCharacter(refChar), encodeExpect);
            errorCollector.checkThat(decodeMsg, uit.decodeCharacter(new PushbackString(expected)), decodeExpect);
        }
    }

    /**
     * If the first element in the {@link PushbackSequence} is null, then null is expected.
     */
    @Test
    public void testAnsiDecodePushbackSequenceNullFirstElementReturnsNull() {
        PushbackSequence<Character> mockPushback = Mockito.mock(PushbackSequence.class);
        Mockito.when(mockPushback.next()).thenReturn(null);
        
        Character decChar = uit.decodeCharacter(mockPushback);
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
        
        Character decChar = uit.decodeCharacter(mockPushback);
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
        
        Character decChar = uit.decodeCharacter(mockPushback);
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
        
        Character decChar = uit.decodeCharacter(mockPushback);
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
        
        Character decChar = uit.decodeCharacter(mockPushback);
        Assert.assertNull(decChar);
        
        Mockito.verify(mockPushback, Mockito.times(1)).mark();
        Mockito.verify(mockPushback, Mockito.times(1)).next();
        Mockito.verify(mockPushback, Mockito.times(1)).reset();
        
    }
}
