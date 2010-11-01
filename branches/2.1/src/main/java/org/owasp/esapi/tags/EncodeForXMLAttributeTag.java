package org.owasp.esapi.tags;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body for use in a XML attribute.
 */
public class EncodeForXMLAttributeTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage as a XML attribute.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForXMLAttribute(String)}
	 * @return content encoded for usage as a XML attribute
	 */
	protected String encode(String content, Encoder enc)
	{
		return enc.encodeForXMLAttribute(content);
	}
}
