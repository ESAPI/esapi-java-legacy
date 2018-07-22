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

public interface LogScrubber {

    /**
     * Returns an Array of String elements representing the cleaned toString() value of each Object in the provided array.
     * </br>
     * Index references are retained such that the String in index 0 of the return Array represents the Object at index 0 in the argument.
     * @param ref Array of elements to create clean String representations for.
     * @return String Array of cleaned content.
     */
    public String[] cleanArrayAsStrings(Object[] ref);
    
    /**
     * Cleans the toString() value of the argument object and returns it to the caller.
     * @param ref Object to clean for output.
     * @return cleaned String
     */
    public String cleanObjectAsString(Object ref);
    
    /**
     * Removes newline characters from the provided String then encodes it for HTML before returning the 'clean' version
     * to the caller.
     * 
     * @param toClean
     *            Original String to clean.
     * @param asFormattedMessage Specifying {@code true} will add the SLF4J message formatting constants to the encoding immunity list.  {@code false} will use the esapi-default html encoding.
     * @return Cleaned String.
     */
    public String cleanString(String toClean, boolean asFormattedMessage);
    /**
     * Removes newline characters from the provided String then encodes it for HTML before returning the 'clean' version
     * to the caller.
     * 
     * @param message
     *            Original message to clean.
     * @return Cleaned message.
     */
    public String cleanMessage(String message);


}
