package org.owasp.esapi.tags;

import java.io.IOException;

import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;
import javax.servlet.jsp.tagext.BodyTagSupport;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

/**
 *
 * @author jwilliams
 */
public class EncodeForHTMLJavaScriptTag extends BodyTagSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2L;
	
    /**
     *
     * @return
     * @throws javax.servlet.jsp.JspTagException
     */
    public int doAfterBody() throws JspTagException {

		
		try {
			
			BodyContent body = getBodyContent();
			
			String content = body.getString();
			JspWriter out = body.getEnclosingWriter();
			
			Encoder e = ESAPI.encoder();
			
			out.print( e.encodeForJavaScript(content) );
			body.clearBody();
			
			return SKIP_BODY;
			
		} catch (IOException ioe) {
			throw new JspTagException("error writing to body's enclosing writer",ioe);
		}
		
	}
}
