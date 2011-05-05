package org.owasp.esapi.tags;

import java.io.UnsupportedEncodingException;

import javax.servlet.jsp.JspTagException;

import org.owasp.esapi.Encoder;

/**
 * JSP tag that encode's it's body using Base64.
 */
public class EncodeForBase64Tag extends BaseEncodeTag
{
	private static final long serialVersionUID = 3L;
	/** @serial Flag determining line wrapping */
	private boolean wrap = false;
	/**
	  * @serial Charset to use when converting content from a String
	  * to byte[].
	  */
	private String encoding = "UTF-8";

	/**
	 * Encode tag's content using Base64.
	 * @param content The tag's content as a String
	 * @param enc Encoder used to call
	 * 	{@link Encoder#encodeForBase64(byte[], boolean)}
	 * @return content encoded in Base64
	 */
	protected String encode(String content, Encoder enc) throws JspTagException
	{
		try
		{
			return enc.encodeForBase64(content.getBytes(encoding), wrap);
		}
		catch(UnsupportedEncodingException e)
		{
			throw new JspTagException("Unsupported encoding " + enc,e);
		}
	}

	/**
	 * Set the encoding used to convert the content to bytes for
	 * encoding. This defaults to UTF-8 if not specified.
	 * @param encoding The encoding passed to {@link String#getBytes(String)}.
	 */
	public void setEncoding(String encoding)
	{
		this.encoding=encoding;
	}

	/**
	 * Get the encoding used to convert the content to bytes for
	 * encoding.
	 * @return encoding The encoding passed to
	 * {@link String#getBytes(String)}.
	 */
	public String getEncoding()
	{
		return encoding;
	}

	/**
	 * Set whether line wrapping at 64 characters is performed. This
	 * defaults to false.
	 * @param wrap flag determining wrapping.
	 */
	public void setWrap(boolean wrap)
	{
		this.wrap=wrap;
	}

	/**
	 * Get whether line wrapping at 64 characters is performed. This
	 * defaults to false.
	 * @return value of flag determining wrapping.
	 */
	public boolean getWrap()
	{
		return wrap;
	}
}
