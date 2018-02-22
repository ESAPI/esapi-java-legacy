/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008-2018 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 */

package org.owasp.esapi.codecs.percent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.owasp.esapi.codecs.percent.PercentCodecStringTest.PERCENT_CODEC_IMMUNE;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.Test;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.PushbackString;
import org.owasp.esapi.codecs.abstraction.AbstractCodecCharacterTest;

/**
 *  Codec validation focused on the PercentCodec Character-based api.
 *  
 */
public class PercentCodecCharacterTest extends AbstractCodecCharacterTest {
    @Parameters(name = "{0}")
    public static Collection<Object[]> buildTests() {
        Collection<Object[]> tests = new ArrayList<>();
        Collection<CodecCharacterTestTuple> tuples = new ArrayList<>();

        tuples.add(newTuple("%3C", Character.valueOf('<')));

        tuples.add(newTuple("%00", Character.MIN_VALUE));
        tuples.add(newTuple("%3D", '='));
        tuples.add(newTuple("%26", '&'));

        for (char c : PERCENT_CODEC_IMMUNE) {
            tuples.add(newTuple(Character.toString(c), c));
        }

        for (CodecCharacterTestTuple tuple : tuples) {
            tests.add(new Object[] { tuple });
        }

        return tests;
    }

    private static CodecCharacterTestTuple newTuple(String encodedInput, Character decoded) {
        CodecCharacterTestTuple tuple = new CodecCharacterTestTuple();
        tuple.codec = new PercentCodec();
        tuple.encodeImmune = PERCENT_CODEC_IMMUNE;
        tuple.decodedValue = decoded;
        tuple.input = encodedInput;

        return tuple;
    }

    public PercentCodecCharacterTest(CodecCharacterTestTuple tuple) {
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
        assertEquals(decodedValue, codec.decodeCharacter(pbs));
        assertTrue(startIndex < pbs.index());
    }

    /**
     * tests that when Input is decoded through a PushbackString that null is returned and that the PushbackString index
     * remains unchanged.
     */
    @SuppressWarnings("unchecked")
    private void assertInputIsDecodedToNull() {
        PushbackString pbs = new PushbackString(input);
        int startIndex = pbs.index();
        assertEquals(null, codec.decodeCharacter(pbs));
        assertEquals(startIndex, pbs.index());
    }

}
