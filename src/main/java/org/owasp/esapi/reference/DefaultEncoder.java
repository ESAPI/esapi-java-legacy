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
package org.owasp.esapi.reference;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Base64;
import org.owasp.esapi.codecs.CSSCodec;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.JavaScriptCodec;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.VBScriptCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

// import sun.text.Normalizer;

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically identified in a
 * list of "immune" characters is encoded. Several methods follow the approach in the <a
 * href="http://www.microsoft.com/downloads/details.aspx?familyid=efb9c819-53ff-4f82-bfaf-e11625130c25&displaylang=en">Microsoft
 * AntiXSS Library</a>.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class DefaultEncoder implements org.owasp.esapi.Encoder {

	// Codecs
	List codecs = new ArrayList();
	private HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
	private PercentCodec percentCodec = new PercentCodec();
	private JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
	private VBScriptCodec vbScriptCodec = new VBScriptCodec();
	private CSSCodec cssCodec = new CSSCodec();
	
	private final Logger logger = ESAPI.getLogger("Encoder");
	
	/**
	 *  Character sets that define characters (in addition to alphanumerics) that are
	 * immune from encoding in various formats
	 */
	private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_CSS = { ' ' };  // TODO: check
	private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_VBSCRIPT = { ' ' };  // TODO: check
	private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_SQL = { ' ' };
	private final static char[] IMMUNE_OS = { '-' };
	private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };

	// initialize the character arrays in sorted order for faster searching
	static {
        Arrays.sort( DefaultEncoder.IMMUNE_HTML );
        Arrays.sort( DefaultEncoder.IMMUNE_HTMLATTR );
        Arrays.sort( DefaultEncoder.IMMUNE_JAVASCRIPT );
        Arrays.sort( DefaultEncoder.IMMUNE_VBSCRIPT );
        Arrays.sort( DefaultEncoder.IMMUNE_XML );
        Arrays.sort( DefaultEncoder.IMMUNE_XMLATTR );
        Arrays.sort( DefaultEncoder.IMMUNE_XPATH );
        Arrays.sort( DefaultEncoder.CHAR_LOWERS );
        Arrays.sort( DefaultEncoder.CHAR_UPPERS );
        Arrays.sort( DefaultEncoder.CHAR_DIGITS );
        Arrays.sort( DefaultEncoder.CHAR_SPECIALS );
        Arrays.sort( DefaultEncoder.CHAR_LETTERS );
        Arrays.sort( DefaultEncoder.CHAR_ALPHANUMERICS );
        Arrays.sort( DefaultEncoder.CHAR_PASSWORD_LOWERS );
        Arrays.sort( DefaultEncoder.CHAR_PASSWORD_UPPERS );
        Arrays.sort( DefaultEncoder.CHAR_PASSWORD_DIGITS );
        Arrays.sort( DefaultEncoder.CHAR_PASSWORD_SPECIALS );
        Arrays.sort( DefaultEncoder.CHAR_PASSWORD_LETTERS );
	}
	
	
	/**
	 * Instantiates a new DefaultEncoder
	 */
	public DefaultEncoder() {
		// initialize the codec list to use for canonicalization
		codecs.add( htmlCodec );
		codecs.add( percentCodec );
		codecs.add( javaScriptCodec );

		// leave this out because it eats / characters
		// codecs.add( cssCodec );

		// leave this out because it eats " characters
		// codecs.add( vbScriptCodec );
	}

	/**
	 * Instantiates a new DefaultEncoder
	 * 
	 * @param codecs A list of codecs to use by the Encoder class
	 * @throws java.lang.IllegalArgumentException If the encoder is not an instance of the Codec interface
	 */
	public DefaultEncoder( List codecs ) {
	    Iterator i = codecs.iterator();
	    while ( i.hasNext() ) {
	       Object o = i.next();
	       if ( !( o instanceof Codec ) ){
	           throw new java.lang.IllegalArgumentException( "Codec list must contain only Codec instances" );
	       }
	    }
	    this.codecs = codecs;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String canonicalize( String input ) {
		if ( input == null ) {
			return null;
		}
		return canonicalize( input, true );
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String canonicalize( String input, boolean strict ) {
		if ( input == null ) {
			return null;
		}
		
        String working = input;
        Codec codecFound = null;
        boolean mixed = false;
        int foundCount = 0;
        boolean clean = false;
        while( !clean ) {
            clean = true;
            
            // try each codec and keep track of which ones work
            Iterator i = codecs.iterator();
            while ( i.hasNext() ) {
                Codec codec = (Codec)i.next();
                String old = working;
                working = codec.decode( working );
                if ( !old.equals( working ) ) {
                    if ( codecFound != null && codecFound != codec ) {
                        mixed = true;
                    }
                    codecFound = codec;
                    if ( clean ) {
                        foundCount++;
                    }
                    clean = false;
                }
            }
        }
        
        // do strict tests and handle if any mixed, multiple, nested encoding were found
        if ( foundCount >= 2 && mixed ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Multiple and mixed encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY, false, "Multiple ("+ foundCount +"x) and mixed encoding detected in " + input );
            }
        }
        else if ( foundCount >= 2 ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Multiple encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY, false, "Multiple ("+ foundCount +"x) encoding detected in " + input );
            }
        }
        else if ( mixed ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Mixed encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY, false, "Mixed encoding detected in " + input );
            }
        }
        return working;
	}
	

	/**
	 * {@inheritDoc}
	 */
	public String normalize(String input) {
		// Split any special characters into two parts, the base character and
		// the modifier
		
        // String separated = Normalizer.normalize(input, Normalizer.DECOMP, 0);  // Java 1.4
		// String separated = Normalizer.normalize(input, Form.NFD);   // Java 1.6

		// remove any character that is not ASCII
		// return separated.replaceAll("[^\\p{ASCII}]", "");
		return input.replaceAll("[^\\p{ASCII}]", "");
	}

	/**
	 * Private helper method to encode a single character by a particular
	 * codec. Will not encode characters from the base and special white lists. 
	 * <p>
	 * Note: It is strongly recommended that you canonicalize input before calling 
	 * this method to prevent double-encoding.
	 *   
	 * @param c - character to be encoded 
	 * @param codec - codec to be used to encode c
	 * @param baseImmune - white list of base characters that are okay
	 * @param specialImmune - white list of special characters that are okay
	 * @return encoded character. NB: Extremely likely that the return string contains more than one character!
	 */
	private String encode( char c, Codec codec, char[] baseImmune, char[] specialImmune ) {
		if (isContained(baseImmune, c) || isContained(specialImmune, c)) {
			return ""+c;
		} else {
			return codec.encodeCharacter( new Character( c ) );
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForHTML(String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			if ( c == '\t' || c == '\n' || c == '\r' ) {
				sb.append( c );
			} else if ( c <= 0x1f || ( c >= 0x7f && c <= 0x9f ) ) {
				logger.warning( Logger.SECURITY, false, "Attempt to HTML entity encode illegal character: " + (int)c + " (skipping)" );
				sb.append( ' ' );
			} else {
				sb.append( encode( c, htmlCodec, CHAR_ALPHANUMERICS, IMMUNE_HTML ) );
			}
		}
		return sb.toString();
	 }
	 
	 
	/**
	 * {@inheritDoc}
	 */
	public String encodeForHTMLAttribute(String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, htmlCodec, CHAR_ALPHANUMERICS, IMMUNE_HTMLATTR ) );
		}
		return sb.toString();
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForCSS(String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			if ( c != 0 ) {
				sb.append( encode( c, cssCodec, CHAR_ALPHANUMERICS, IMMUNE_CSS ) );
			}
		}
		return sb.toString();
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForJavaScript(String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, javaScriptCodec, CHAR_ALPHANUMERICS, IMMUNE_JAVASCRIPT ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForVBScript(String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, vbScriptCodec, CHAR_ALPHANUMERICS, IMMUNE_VBSCRIPT ) );
		}
		return sb.toString();
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForSQL(Codec codec, String input) {
	    if( input == null ) {
	    	return null;
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, codec, CHAR_ALPHANUMERICS, IMMUNE_SQL ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForOS(Codec codec, String input) {
	    if( input == null ) {
	    	return null;	
	    }
	    
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, codec, CHAR_ALPHANUMERICS, IMMUNE_OS ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForLDAP(String input) {
	    if( input == null ) {
	    	return null;	
	    }
		// TODO: replace with LDAP codec
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			switch (c) {
			case '\\':
				sb.append("\\5c");
				break;
			case '*':
				sb.append("\\2a");
				break;
			case '(':
				sb.append("\\28");
				break;
			case ')':
				sb.append("\\29");
				break;
			case '\0':
				sb.append("\\00");
				break;
			default:
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForDN(String input) {
	    if( input == null ) {
	    	return null;	
	    }
		// TODO: replace with DN codec
		StringBuffer sb = new StringBuffer();
		if ((input.length() > 0) && ((input.charAt(0) == ' ') || (input.charAt(0) == '#'))) {
			sb.append('\\'); // add the leading backslash if needed
		}
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			switch (c) {
			case '\\':
				sb.append("\\\\");
				break;
			case ',':
				sb.append("\\,");
				break;
			case '+':
				sb.append("\\+");
				break;
			case '"':
				sb.append("\\\"");
				break;
			case '<':
				sb.append("\\<");
				break;
			case '>':
				sb.append("\\>");
				break;
			case ';':
				sb.append("\\;");
				break;
			default:
				sb.append(c);
			}
		}
		// add the trailing backslash if needed
		if ((input.length() > 1) && (input.charAt(input.length() - 1) == ' ')) {
			sb.insert(sb.length() - 1, '\\');
		}
		return sb.toString();
	}


	/**
	 * {@inheritDoc}
	 */
	public String encodeForXPath(String input) {
	    if( input == null ) {
	    	return null;	
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, htmlCodec, CHAR_ALPHANUMERICS, IMMUNE_XPATH ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXML(String input) {
	    if( input == null ) {
	    	return null;	
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, htmlCodec, CHAR_ALPHANUMERICS, IMMUNE_XML ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXMLAttribute(String input) {
	    if( input == null ) {
	    	return null;	
	    }
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encode( c, htmlCodec, CHAR_ALPHANUMERICS, IMMUNE_XMLATTR ) );
		}
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForURL(String input) throws EncodingException {
		if ( input == null ) {
			return null;
		}
		try {
			return URLEncoder.encode(input, ESAPI.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Encoding failure", "Encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Encoding failure", "Problem URL decoding input", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String decodeFromURL(String input) throws EncodingException {
		if ( input == null ) {
			return null;
		}
		String canonical = canonicalize(input);
		try {
			return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Decoding failed", "Encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForBase64(byte[] input, boolean wrap) {
		if ( input == null ) {
			return null;
		}
		int options = 0;
		if ( !wrap ) {
			options |= Base64.DONT_BREAK_LINES;
		}
		return Base64.encodeBytes(input, options);
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] decodeFromBase64(String input) throws IOException {
		if ( input == null ) {
			return null;
		}
		return Base64.decode( input );
	}

	
	/**
	 * isContained is a helper method which determines if c is 
	 * contained in the character array. For performance reasons, the
	 * character array must be sorted or the results are not
	 * guaranteed.
	 * 
	 * @param array
	 *		a sorted character array containing a set of characters to be searched
	 * @param c 
	 *      a character to be searched for
	 * @return  
	 *      true if c is in array, false otherwise
	 */
	protected boolean isContained(char[] array, char c) {
	    // Arrays are sorted in the static initializer
		// for (int i = 0; i < array.length; i++) {
		//	 if (c == array[i]) return true;
		// }
		// return false;
		
		// If sorted arrays are guaranteed, this is faster
		return( Arrays.binarySearch(array, c) >= 0 );
	}

    
}