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
package org.owasp.esapi.reference.regex;

import static org.junit.Assert.assertEquals;

import java.util.regex.Pattern;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Abstract parameterized test case meant to assist with verifying regular expressions in test scope.
 * <br/>
 * Sub-classes are expected to provide instances of {@link PatternTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link PatternTestTuple#description} and use <code> @Parameters (name="{0}")</code>,
 * where '0' is the index that the PatternTestTuple reference appears in the constructor.
 */
@RunWith(Parameterized.class)
public abstract class AbstractPatternTest {

    /**
     * Test tuple for Pattern validation.
     */
    protected static class PatternTestTuple {
        /** String value to be tested against the compiled regex reference. */
        String input;
        /** Regular expression string that will be compiled and be passed the input. */
        String regex;
        /** Test Expectation whether input should match the compiled regex. */
        boolean shouldMatch;
        /** Optional field to override the toString value of this tuple. */
        String description;

        /** {@inheritDoc} */
        @Override
        public String toString() {
            return description != null ? description : regex;
        }
    }

    private String input;
    private Pattern pattern;
    private boolean shouldMatch;

    public AbstractPatternTest(PatternTestTuple tuple) {
        this.input = tuple.input;
        this.pattern = Pattern.compile(tuple.regex);
        this.shouldMatch = tuple.shouldMatch;
    }

    @Test
    public void checkPatternMatches() {
        assertEquals(shouldMatch, pattern.matcher(input).matches());
    }

}
