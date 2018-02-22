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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.abstraction.AbstractCodecStringTest;

/**
 *  Codec validation focused on the PercentCodec String-based api.
 *  
 */
public class PercentCodecStringTest extends AbstractCodecStringTest {
    public static final char[] PERCENT_CODEC_IMMUNE;

    static {
        /*
         * The percent codec contains a unique immune character set which include letters and numbers that will not be transformed.
         * 
         * It is being replicated here to allow the test to reasonably expect the correct state back.
         */
        List<Character> immune = new ArrayList<>();
        // 65 - 90 (capital letters in ASCII) 97 - 122 lower case 48 - 57 digits
        //numbers
        for (int index = 48 ; index < 58; index ++) {
            immune.add((char)index);
        }
        //letters
        for (int index = 65 ; index < 91; index ++) {
            Character capsChar = (char)index;
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
        List<CodecStringTestTuple> tuples = new ArrayList<>();
        
        tuples.add(newTuple("%3C", "<"));
        tuples.add(newTuple("%00", Character.MIN_VALUE));
        tuples.add(newTuple("%3D", '='));
        tuples.add(newTuple("%26", '&'));

        for (char c : PERCENT_CODEC_IMMUNE) {
            tuples.add(newTuple(Character.toString(c), c));
        }
        
        for (CodecStringTestTuple tuple : tuples) {
            tests.add(new Object[] { tuple });
        }

        return tests;
    }

    private static CodecStringTestTuple newTuple(String input, Object decoded) {
        CodecStringTestTuple tuple = new CodecStringTestTuple();
        tuple.codec = new PercentCodec();
        tuple.encodeImmune = PERCENT_CODEC_IMMUNE;
        tuple.decodedValue = decoded.toString();
        tuple.input = input;

        return tuple;
    }

    /**
     * @param tuple
     */
    public PercentCodecStringTest(CodecStringTestTuple tuple) {
        super(tuple);
    }

}
