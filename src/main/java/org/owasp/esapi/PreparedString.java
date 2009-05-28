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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;


/**
 * A parameterized string that can be used to send data to an interpreter.
 * 
 * PreparedString div = new PreparedString( “<a href=”@1” onmouseover=”alert(‘@2’)”>test</a>” );
 * div.setURL( 1, request.getParameter( “url” ) );
 * div.setJavaScriptString( 2, request.getParameter( “message” ) );
 * out.println( div.toString() );
 * 
 * // escaping for SQL
 * PreparedString query = new PreparedString( “SELECT * FROM users WHERE name=@1 AND password=@2” );
 * query.setSQLString( 1, request.getParameter( “name” ) );
 * query.setSQLString( 1, request.getParameter( “pass” ) );
 * stmt.execute( query.toString() );
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class PreparedString {
	String template = null;
	char parameterCharacter = '@';
	
	public PreparedString( String template ) {
		this.template = template;
	}
	
	public void setParameterCharacter( char c ) {
		parameterCharacter = c;
	}
	
	/// FIXME: xxx
	
}
