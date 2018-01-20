package org.owasp.esapi.reference;

import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;


/**
 * FIXME:  Document intent of class.  General Function, purpose of creation, intended feature, etc.
 *  Why do people care this exists? 
 * @author Jeremiah
 * @since Jan 20, 2018
 *
 */
@RunWith (Parameterized.class)
public abstract class AbstractPatternTest {
    
    protected static class PatternTestTuple {
        String input;
        String regex;
        boolean shouldMatch;
        String description;
        /** {@inheritDoc}*/        
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
