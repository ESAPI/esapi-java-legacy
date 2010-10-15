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

import java.io.IOException;

import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyTagSupport;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

/** Abstract base class for tags that just encode their bodies with Encoder methods. */
public abstract class BaseEncodeTag extends BodyTagSupport
{
	private static final long serialVersionUID = 1L;

	/**
	 * Encode tag's content.
	 * @param content The tag's content as a String
	 * @param enc Encoder provided as a convinence.
	 * @return content encoded by the subclass's implementation.
	 */
	protected abstract String encode(String content, Encoder enc) throws JspTagException;

	/**
	 * After tag body parsing handler. This provides the necessary
	 * plubming to allow subclasses to just concern themselves with
	 * encoding a single string.
	 * @return {@link javax.servlet.jsp.tagext.Tag#SKIP_BODY}
	 * @throws JspTagException if writing to the bodyContent's
	 * enclosing writer throws an IOException.
	 */
	public int doAfterBody() throws JspTagException
	{
		String content;
		JspWriter out;

		content = bodyContent.getString();
		out = bodyContent.getEnclosingWriter();

		content = encode(content, ESAPI.encoder());
		try
		{
			out.print(content);
		}
		catch (IOException e)
		{
			throw new JspTagException("Error writing to body's enclosing JspWriter",e);
		}

		bodyContent.clearBody();
		return SKIP_BODY;
	}
}
