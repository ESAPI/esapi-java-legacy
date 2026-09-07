package org.owasp.esapi.codecs.ref;

import java.util.regex.Pattern;

import org.junit.Test;

import static org.junit.Assert.*;

public class EncodingPatternPreservationTest {

    @Test
    public void testReplaceAndRestore() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 DEF 56 G 7";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertFalse("Replaced string should no longer contain the matched pattern", replacedStr.contains("ABC"));
        assertTrue(replacedStr.startsWith("12 EncodingPatternPreservation"));
        assertTrue(replacedStr.endsWith(" 34 DEF 56 G 7"));

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }

    @Test
    public void testReplaceMultipleAndRestore() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 ABC 56 G 7 ABC8";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertFalse("Replaced string should no longer contain the matched pattern", replacedStr.contains("ABC"));

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }

    @Test
    public void testDefaultMarkerIsUnpredictablePerInstance() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp1 = new EncodingPatternPreservation(numberRegex);
        EncodingPatternPreservation epp2 = new EncodingPatternPreservation(numberRegex);

        String replaced1 = epp1.captureAndReplaceMatches("ABC");
        String replaced2 = epp2.captureAndReplaceMatches("ABC");

        assertNotEquals("Default marker must not be a fixed, guessable value shared across instances",
                replaced1, replaced2);
    }

    @Test
    public void testInputContainingLiteralClassNameDoesNotDesyncRestoration() {
        // Regression test: previously the default marker was the fixed literal
        // "EncodingPatternPreservation", so input already containing that literal
        // string ahead of real matched content would be restored in place of the
        // real match, desynchronizing every subsequent restoreFirst() call.
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "EncodingPatternPreservation prefix ABC suffix";

        String replacedStr = epp.captureAndReplaceMatches(origStr);
        String restored = epp.restoreOriginalContent(replacedStr);

        assertEquals(origStr, restored);
    }

    @Test
    public void testSetMarker() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        epp.setReplacementMarker(EncodingPatternPreservationTest.class.getSimpleName());

        String origStr = "12 ABC 34 DEF 56 G 7";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertEquals("12 EncodingPatternPreservationTest 34 DEF 56 G 7", replacedStr);

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }

    @Test (expected = IllegalStateException.class)
    public void testSetMarkerExceptionNoReset() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 DEF 56 G 7";
        epp.captureAndReplaceMatches(origStr);
        //This allows the + case to be illustrated
        epp.reset();

        //And the exception case.
        epp.captureAndReplaceMatches(origStr);
        epp.setReplacementMarker(EncodingPatternPreservationTest.class.getSimpleName());
    }

    @Test (expected = IllegalStateException.class)
    public void testReplaceExceptionNoReset() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 DEF 56 G 7";
        epp.captureAndReplaceMatches(origStr);
        //This allows the + case to be illustrated
        epp.reset();

        //And the exception case.
        epp.captureAndReplaceMatches(origStr);
        epp.captureAndReplaceMatches(origStr);
    }
}
