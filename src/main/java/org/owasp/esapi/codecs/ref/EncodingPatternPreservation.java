package org.owasp.esapi.codecs.ref;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * String mutation utility which can be used to replace all occurrences of a
 * defined regular expression with a marker string, and also restore the
 * original string content.
 *
 */
public class EncodingPatternPreservation {
    /** Default replacement marker. */
    private static final String REPLACEMENT_MARKER = EncodingPatternPreservation.class.getSimpleName();
    /** Pattern that is used to identify which content should be replaced. */
    private final Pattern noEncodeContent;
    /** The Marker used to replace found Pattern references. */
    private String replacementMarker = REPLACEMENT_MARKER;

    /**
     * The ordered-list of elements that were replaced in the last call to
     * {@link #captureAndReplaceMatches(String)}, and that will be used to replace
     * the {@link #replacementMarker} on the next call to
     * {@link #restoreOriginalContent(String)}
     */
    private final List<String> replacedContentList = new ArrayList<>();

    /**
     * Constructor.
     * 
     * @param pattern Pattern identifying content being replaced.
     */
    public EncodingPatternPreservation(Pattern pattern) {
        noEncodeContent = pattern;
    }

    /**
     * Replaces each matching instance of this instance's Pattern with an
     * identifiable replacement marker. <br>
     * 
     * <br>
     * After the encoding process is complete, use
     * {@link #restoreOriginalContent(String)} to re-insert the original data.
     * 
     * @param input String to adjust
     * @return The adjusted String
     */
    public String captureAndReplaceMatches(String input) {
        if (!replacedContentList.isEmpty()) {
            // This may seem odd, but this will prevent programmer error that would result
            // in being unable to restore a previously tokenized String.
            String message = "Previously captured state is still present in instance. Call PatternContentPreservation.reset() to clear out preserved state and to reuse the reference.";
            throw new IllegalStateException(message);
        }
        String inputCpy = input;
        Matcher matcher = noEncodeContent.matcher(input);

        while (matcher.find()) {
            String replaceContent = matcher.group(0);
            if (replaceContent != null) {
                replacedContentList.add(replaceContent);
                inputCpy = inputCpy.replaceFirst(noEncodeContent.pattern(), replacementMarker);
            }            
        }

        return inputCpy;
    }

    /**
     * Replaces each instance of the {@link #replacementMarker} with the original
     * content, as captured by {@link #captureAndReplaceMatches(String)}
     * 
     * @param input String to restore.
     * @return String reference with all values replaced.
     */
    public String restoreOriginalContent(String input) {
        String result = input;
        while (replacedContentList.size() > 0) {
            String origValue = replacedContentList.remove(0);
            result = result.replaceFirst(replacementMarker, origValue);
        }

        return result;

    }

    /**
     * Allows the marker used as a replacement to be altered.
     * 
     * @param marker String replacment to use for regex matches.
     */
    public void setReplacementMarker(String marker) {
        if (!replacedContentList.isEmpty()) {
            // This may seem odd, but this will prevent programmer error that would result
            // in being unable to restore a previously tokenized String.
            String message = "Previously captured state is still present in instance. Call PatternContentPreservation.reset() to clear out preserved state and to alter the marker.";
            throw new IllegalStateException(message);
        }
        this.replacementMarker = marker;
    }

    /**
     * Clears any stored replacement values out of the instance.
     */
    public void reset() {
        replacedContentList.clear();
    }

}
