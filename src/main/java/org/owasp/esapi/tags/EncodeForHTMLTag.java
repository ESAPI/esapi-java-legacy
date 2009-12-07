/*
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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */

package org.owasp.esapi.tags;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body for use in HTML.
 */
public class EncodeForHTMLTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage in HTML.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForHTML(String)}
	 * @return content encoded for usage in HTML
	 */
	protected String encode(String content, Encoder enc)
	{
		return enc.encodeForHTML(content);
	}
}
