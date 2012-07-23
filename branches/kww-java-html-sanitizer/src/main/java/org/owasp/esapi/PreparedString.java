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
 * @created 2009
 */
package org.owasp.esapi;

import java.util.ArrayList;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;


/**
 * A parameterized string that uses escaping to make untrusted data safe before combining it with
 * a command or query intended for use in an interpreter.
 * <pre> 
 * PreparedString div = new PreparedString( "&lt;a href=\"http:\\\\example.com?id=?\" onmouseover=\"alert('?')\"&gt;test&lt;/a&gt;", new HTMLEntityCodec() );
 * div.setURL( 1, request.getParameter( "url" ), new PercentCodec() );
 * div.set( 2, request.getParameter( "message" ), new JavaScriptCodec() );
 * out.println( div.toString() );
 * 
 * // escaping for SQL
 * PreparedString query = new PreparedString( "SELECT * FROM users WHERE name='?' AND password='?'", new OracleCodec() );
 * query.set( 1, request.getParameter( "name" ) );
 * query.set( 2, request.getParameter( "pass" ) );
 * stmt.execute( query.toString() );
 * </pre>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class PreparedString {
	char parameterCharacter = '?';
	Codec codec = null;
	String[] parameters = null;
	ArrayList parts = new ArrayList();
	private final static char[] IMMUNE = {};

	/**
	 * Create a PreparedString with the supplied template and Codec. The template should use the 
	 * default parameter placeholder character (?) in the place where actual parameters are to be inserted.
	 * The supplied Codec will be used to escape characters in calls to set, unless a specific Codec is
	 * provided to override it.
	 * @param template
	 * @param codec
	 */
	public PreparedString( String template, Codec codec ) {
		this.codec = codec;
		split( template, parameterCharacter );
	}

	/**
	 * Create a PreparedString with the supplied template, parameter placeholder character, and Codec. The parameter character
	 * can be any character, but should not be one that will be used in the template. The parameter character can safely
	 * be used in a parameter passed into the set methods.
	 * @param template
	 * @param parameterCharacter
	 * @param codec
	 */
	public PreparedString( String template, char parameterCharacter, Codec codec ) {
		this.codec = codec;
		this.parameterCharacter = parameterCharacter;
		split( template, parameterCharacter );
	}

	/**
	 * Split a string with a particular character.
	 * @param str
	 * @param c
	 */
	private void split( String str, char c ) {
		int index = 0;
		int pcount = 0;
		for ( int i = 0; i < str.length(); i++ ) {
			if ( str.charAt(i) == c ) {
				pcount++;
				parts.add( str.substring(index,i) );
				index = i + 1;
			}
		}
		parts.add( str.substring(index) );
		parameters = new String[pcount];
	}
	
	/**
	 * Set the parameter at index with supplied value using the default Codec to escape. 
	 * @param index
	 * @param value
	 */
	public void set( int index, String value ) {
		if ( index < 1 || index > parameters.length ) {
			throw new IllegalArgumentException( "Attempt to set parameter " + index + " on a PreparedString with only " + parameters.length + " placeholders" );
		}
		String encoded = codec.encode( IMMUNE, value );
		parameters[index-1] = encoded;
	}
	
	/**
	 * Set the parameter at index with supplied value using the supplied Codec to escape. 
	 * @param index
	 * @param value
	 * @param codec
	 */
	public void set( int index, String value, Codec codec ) {
		if ( index < 1 || index > parameters.length ) {
			throw new IllegalArgumentException( "Attempt to set parameter " + index + " on a PreparedString with only " + parameters.length + " placeholders" );
		}
		String encoded = codec.encode( IMMUNE, value );
		parameters[index-1] = encoded;
	}
	
	/**
	 * Render the PreparedString by combining the template with properly escaped parameters.
	 */
	public String toString() {
		for ( int ix = 0; ix < parameters.length; ix++ ) {
			if ( parameters[ix] == null ) {
				throw new RuntimeException( "Attempt to render PreparedString without setting parameter " + ( ix + 1 ));
			}
		}
		StringBuilder sb = new StringBuilder();
		int i = 0;
		for ( int p=0; p < parts.size(); p++ ) {
			sb.append( parts.get( p ) );
			if ( i < parameters.length ) sb.append( parameters[i++] );
		}
		return sb.toString();
	}
}
