package org.owasp.esapi.tags;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body for use in XPath.
 */
public class EncodeForXPathTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage in XPath.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForXPath(String)}
	 * @return content encoded for usage in XPath
	 */
	protected String encode(String content, Encoder enc)
	{
		return enc.encodeForXPath(content);
	}
}
