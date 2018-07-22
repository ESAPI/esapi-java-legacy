/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @created 2018
 */
package org.owasp.esapi.logging.slf4j;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

public class CodecLogScrubber implements LogScrubber {
    /* NewLine and Carriage Return Replacement values.*/
    private static final char NEWLINE = '\n';
    private static final char CARRIAGE_RETURN = '\r';
    private static final char LINE_WRAP_REPLACE = '_';
    
    
    private final Codec<?> customizedMessageCodec;
    private final char[] immuneMessageChars;
    
    public  CodecLogScrubber (Codec<?> messageCodec, char[] immuneChars) {
        this.customizedMessageCodec = messageCodec;
        this.immuneMessageChars = immuneChars;
    }
    
    /**
     * Returns an Array of String elements representing the cleaned toString() value of each Object in the provided array.
     * </br>
     * Index references are retained such that the String in index 0 of the return Array represents the Object at index 0 in the argument.
     * @param ref Array of elements to create clean String representations for.
     * @return String Array of cleaned content.
     */
    public final String[] cleanArrayAsStrings(Object[] ref) {
        String[] cleaned = new String[ref.length];
        for (int index = 0; index < ref.length; index ++) {
            cleaned[index] = cleanObjectAsString(ref[index]);
        }
        return cleaned;
    }
    
    /**
     * Cleans the toString() value of the argument object and returns it to the caller.
     * @param ref Object to clean for output.
     * @return cleaned String
     */
    public final String cleanObjectAsString(Object ref) {
        return cleanString(ref.toString(), false);
    }
    
    /**
     * Removes newline characters from the provided String then encodes before returning the 'clean' version
     * to the caller.
     * 
     * @param toClean
     *            Original String to clean.
     * @param asFormattedMessage Specifying {@code true} will use the specialized message codec and immunity to account for additional message content constraints.  {@code false} will use the esapi-default html encoding.
     * @return Cleaned String.
     */
    public final String cleanString(String toClean, boolean asFormattedMessage) {
        // ensure no CRLF injection into logs for forging records
        String clean = toClean.replace(NEWLINE, LINE_WRAP_REPLACE).replace(CARRIAGE_RETURN, LINE_WRAP_REPLACE);
        
        if (ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_ENCODING_REQUIRED)) {
            if (asFormattedMessage) {
                //Use a more customized html encoder to exclude immune syntax markers for data replacement.
                clean = customizedMessageCodec.encode(immuneMessageChars, clean);
            } else {
                clean = ESAPI.encoder().encodeForHTML(clean);
            }
            
            if (!toClean.equals(clean)) {
                clean += " (Encoded)";
            }
        }
        return clean;
    }
    /**
     * Removes newline characters from the provided String then encodes it for HTML before returning the 'clean' version
     * to the caller.
     * 
     * @param message
     *            Original message to clean.
     * @return Cleaned message.
     */
    public final String cleanMessage(String message) {
       return cleanString(message, true);
    }
}
