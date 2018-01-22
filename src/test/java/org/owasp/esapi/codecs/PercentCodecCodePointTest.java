package org.owasp.esapi.codecs;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.Parameterized.Parameters;

/**
 *  Codec validation focused on the PercentCodec codepoint-based api.
 *  
 */
@Ignore(value="Implementation pending")
public class PercentCodecCodePointTest extends AbstractCodecCodePointTest {
    private static final char[] PERCENT_CODEC_IMMUNE;

    static {
        /*
         * The percent codec contains a unique immune character set which include letters and numbers that will not be
         * transformed.
         * It is being replicated here to allow the test to reasonably expect the correct state back.
         */
        List<Character> immune = new ArrayList<>();
        // 65 - 90 (capital letters) 97 - 122 lower case 48 - 57 digits
        // numbers
        for (int index = 48; index < 58; index++) {
            immune.add((char) index);
        }
        // letters
        for (int index = 65; index < 91; index++) {
            Character capsChar = (char) index;
            immune.add(capsChar);
            immune.add(Character.toLowerCase(capsChar));
        }

        PERCENT_CODEC_IMMUNE = new char[immune.size()];
        for (int index = 0; index < immune.size(); index++) {
            PERCENT_CODEC_IMMUNE[index] = immune.get(index).charValue();
        }
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> buildTests() {
        Collection<Object[]> tests = new ArrayList<>();

        Collection<CodecCodePointTestTuple> tuples = new ArrayList<>();
        tuples.add(newTuple("%3C", Character.valueOf('<')));

        tuples.add(newTuple("%C4%80", Character.valueOf((char) 0x100)));
        tuples.add(newTuple("%00", Character.MIN_VALUE));
        tuples.add(newTuple("%3D", '='));
        tuples.add(newTuple("%26", '&'));

        for (char c : PERCENT_CODEC_IMMUNE) {
            tuples.add(newTuple(Character.toString(c), c));
        }

        for (CodecCodePointTestTuple tuple : tuples) {
            tests.add(new Object[] { tuple });
        }

        return tests;
    }

    private static CodecCodePointTestTuple newTuple(String encodedInput, Character decoded) {
        CodecCodePointTestTuple tuple = new CodecCodePointTestTuple();
        tuple.codec = new PercentCodec();
        tuple.encodeImmune = PERCENT_CODEC_IMMUNE;
        tuple.codePoint = decoded.charValue();
        tuple.input = encodedInput;

        return tuple;
    }

    public PercentCodecCodePointTest(CodecCodePointTestTuple tuple) {
        super(tuple);
    }

    @Override
    @Test
    public void testDecodePushbackSequence() {
        // check duplicated from PushbackSequence handling in PercentCodec.
        boolean inputIsEncoded = input.startsWith("%");

        if (inputIsEncoded) {
            assertInputIsDecodedToValue();
        } else {
            assertInputIsDecodedToNull();
        }
    }

    /**
     * tests that when Input is decoded through a PushbackString that the decodedValue reference is returned and that
     * the PushbackString index has incremented.
     */
    @SuppressWarnings("unchecked")
    private void assertInputIsDecodedToValue() {
        PushbackString pbs = new PushbackString(input);
        int startIndex = pbs.index();
        Character decChar = (Character) codec.decodeCharacter(pbs);
        char actual = decChar.charValue();
        Assert.assertEquals(String.format("%s(%s) != %s(%s)", (char)decodedValue, decodedValue, actual, (int)actual), decodedValue, (int)actual);
        Assert.assertTrue(startIndex < pbs.index());
    }

    /**
     * tests that when Input is decoded through a PushbackString that null is returned and that the PushbackString index
     * remains unchanged.
     */
    @SuppressWarnings("unchecked")
    private void assertInputIsDecodedToNull() {
        PushbackString pbs = new PushbackString(input);
        int startIndex = pbs.index();
        Assert.assertEquals(null, codec.decodeCharacter(pbs));
        Assert.assertEquals(startIndex, pbs.index());
    }

}