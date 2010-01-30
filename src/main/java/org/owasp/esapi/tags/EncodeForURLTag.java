package org.owasp.esapi.tags;

import javax.servlet.jsp.JspTagException;

import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;

/**
 * JSP tag that encode's it's body for use in a URL.
 */
public class EncodeForURLTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage in a URL.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForURL(String)}
	 * @return content encoded for usage in a URL
	 * @throws EncodingException if {@link Encoder#encodeForURL(String)} does.
	 */
	protected String encode(String content, Encoder enc) throws JspTagException
	{
		try
		{
			return enc.encodeForURL(content);
		}
		catch(EncodingException e)
		{
			JspTagException wrapped = new JspTagException("Unable to encode to URL encoding");
			wrapped.initCause(e);
			throw wrapped;
		}
	}
}
