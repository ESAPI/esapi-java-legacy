package org.owasp.esapi.tags;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body for use in JavaScript.
 */
public class EncodeForJavaScriptTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage in JavaScript
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForJavaScript(String)}
	 * @return content encoded for usage in JavaScript
	 */
	protected String encode(String content, Encoder enc)
	{
		return enc.encodeForJavaScript(content);
	}
}
