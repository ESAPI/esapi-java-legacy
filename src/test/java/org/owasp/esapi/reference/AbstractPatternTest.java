package org.owasp.esapi.reference;

import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Abstract parameterized test case meant to assist with verifying regular expressions in test scope.
 * <br/>
 * Sub-classes are expected to provide instances of {@link PatternTestTuple} to this instance.
 * <br/>
 * For better test naming output specify {@link PatternTestTuple#description} and use {@code} @Parameters (name="{0}")},
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
        Assert.assertEquals(shouldMatch, pattern.matcher(input).matches());
    }

}