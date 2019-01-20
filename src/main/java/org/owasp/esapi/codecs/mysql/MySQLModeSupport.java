package org.owasp.esapi.codecs.mysql;

import org.owasp.esapi.codecs.PushbackSequence;

/**
 * Contract for allowing MySQLCodec to apply a strategy pattern to a delegate
 * implementation when encoding and decoding characters.
 * 
 */
public interface MySQLModeSupport {
    /**
     * Converts the specified Character parameter into a potentially multi-Character
     * String representing this instance's encoding behavior.
     * 
     * @param c
     *            Character t encode.
     * @return String value of 1 or more characters representing the encoded value.
     */
    String encodeCharacter(Character c);

    /**
     * Converts the Character represented within the {@link PushbackSequence}
     * reference into the original form from this support instance.
     * 
     * @param input
     *            {@link PushbackSequence} containing the encoded character
     * @return Character that was decoded, or {@code null} if the sequence does not
     *         contain data that can be decoded by this instance.
     */
    Character decodeCharacter(PushbackSequence<Character> input);
}
