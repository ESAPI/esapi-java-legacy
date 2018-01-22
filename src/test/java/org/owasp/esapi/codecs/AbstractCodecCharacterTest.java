package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;


/**
 * Abstract parameterized test case meant to assist with verifying Character api of a Codec implementation.
 * <br/>
 * Sub-classes are expected to provide instances of {@link CodecCharacterTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link CodecCharacterTestTuple#description} and use {@code} @Parameters (name="{0}")},
 * where '0' is the index that the CodecCharacterTestTuple reference appears in the constructor.
 */
@RunWith(Parameterized.class)
public abstract class AbstractCodecCharacterTest {
    
    /** Test Data Tuple.*/
    protected static class CodecCharacterTestTuple {
        /** Codec reference to be tested.*/
        Codec codec;
        /** Set of characters that should be considered 'immune' from decoding processes.*/
        char[] encodeImmune;
        /** A String representing a single encoded character.*/
        String input;
        /** The single character that input represents.*/
        Character decodedValue;
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
    protected final Character decodedValue;
    
    public AbstractCodecCharacterTest(CodecCharacterTestTuple tuple) {
        this.codec = tuple.codec;
        this.input = tuple.input;
        this.decodedValue = tuple.decodedValue;
        this.encodeImmune = tuple.encodeImmune;
    }
    
    /** Checks that the input value matches the result of the codec encoding the decoded value.  */
    @Test
    public void testEncodeCharacter() {
        assertEquals(input, codec.encodeCharacter(encodeImmune, decodedValue));
    }
    
    /** Checks encoding the character as a String.
     * <br/>
     * If the decoded value is in the immunity list, the the decoded value should be returned from the encode call.
     * Otherwise, input is expected as the return. 
     */
    @Test
    public void testEncode() {
        String expected = Arrays.asList(encodeImmune).contains(decodedValue) ? decodedValue.toString() : input;
        assertEquals(expected, codec.encode(encodeImmune, decodedValue.toString()));
    }
    
    /**  Checks that decoding the input value yeilds the decodedValue.*/
    @Test
    public void testDecode() {
         assertEquals(decodedValue.toString(), codec.decode(input));
    }
    
    /** Checks that the encoded input String is correctly decoded to the single decodedValue character reference.*/
    @Test
    public void testDecodePushbackSequence() {
        assertEquals(decodedValue, codec.decodeCharacter(new PushbackString(input)));
    }
    
}