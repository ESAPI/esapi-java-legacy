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
 * @author Pawan Singh (pawan.singh@owasp.org) <a href="www.owasp.org">OWASP</a>
 * @created 2009
 */
package org.owasp.esapi.util;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

import org.owasp.esapi.ESAPI;

/**
 * @author Pawan Singh (pawan.singh@owasp.org)
 *
 */
public class DefaultMessageUtil {

    private final String DEFAULT_LOCALE_LANG = "en";
    private final String DEFAULT_LOCALE_LOC = "US";
    
    private ResourceBundle messages = null;
    
    public void initialize() {
    	try {
                messages = ResourceBundle.getBundle("ESAPI", ESAPI.authenticator().getCurrentUser().getLocale());
        } catch (Exception e) {
                messages = ResourceBundle.getBundle("ESAPI", new Locale(DEFAULT_LOCALE_LANG,DEFAULT_LOCALE_LOC));
        }
    }


	public String getMessage(String msgKey, Object[] arguments) {
		
		initialize();
		return MessageFormat.format( messages.getString(msgKey), arguments );
	}
}