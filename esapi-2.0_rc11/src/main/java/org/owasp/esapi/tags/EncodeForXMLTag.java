package org.owasp.esapi.tags;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body for use in XML.
 */
public class EncodeForXMLTag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;

	/**
	 * Encode tag's content for usage in XML.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForXML(String)}
	 * @return content encoded for usage in XML
	 */
	protected String encode(String content, Encoder enc)
	{
		return enc.encodeForXML(content);
	}
}
