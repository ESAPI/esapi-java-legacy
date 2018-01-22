package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;


/**
 * Abstract parameterized test case meant to assist with verifying Character api of a Codec implementation.
 * <br/>
 * Sub-classes are expected to provide instances of {@link CodecCodePointTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link CodecCodePointTestTuple#description} and use {@code} @Parameters (name="{0}")},
 * where '0' is the index that the CodecCodePointTestTuple reference appears in the constructor.
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecCodePointTest {
    
    /** Test Data Tuple.*/
    protected static class CodecCodePointTestTuple {
        /** Codec reference to be tested.*/
        Codec codec;
        /** Set of characters that should be considered 'immune' from decoding processes.*/
        char[] encodeImmune;
        /** A String representing a single encoded character.*/
        String input;
        /** The int code point that input represents.*/
        int codePoint;
        /** Optional field to override the toString value of this tuple. */
        String description;
        /** {@inheritDoc}*/
        
        @Override
        public String toString() {
            return description != null ? description : codec.getClass().getSimpleName() + "  "+input;
        }
    }

    
    protected final Codec codec;
    protected final String input;
    protected final char[] encodeImmune;
    protected final int decodedValue;
    protected final char codePointChar;
    
    public AbstractCodecCodePointTest(CodecCodePointTestTuple tuple) {
        this.codec = tuple.codec;
        this.input = tuple.input;
        this.decodedValue = tuple.codePoint;
        this.encodeImmune = tuple.encodeImmune;
        this.codePointChar = (char) tuple.codePoint;
    }
    
    /** Checks that the input value matches the result of the codec encoding the decoded value.  */
    @Test
    public void testEncodeCharacter() {
        assertEquals(input, codec.encodeCharacter(encodeImmune, decodedValue));
    }
    
    /**  Checks that decoding the input value yeilds the same code point decodedValue.*/
    @Test
    public void testDecode() {
        int expectedLength = Character.toString(codePointChar).length();
        String actualDecode = codec.decode(input);
        assertTrue("CodePoint test input should decode to a String consisting of a single character:  " + actualDecode + " " + actualDecode.length(),actualDecode.length() == expectedLength);
         assertEquals(decodedValue, (int)actualDecode.charAt(0));
    }
    
    /** Checks that the encoded input String is correctly decoded to the single decodedValue character reference.*/
    @Test
    public void testDecodePushbackSequence() {
        assertEquals(decodedValue, codec.decodeCharacter(new PushbackString(input)));
    }
    
}
