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
 * list of "immune" characters is encoded.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class DefaultEncoder implements org.owasp.esapi.Encoder {

	// Codecs
	private List codecs = new ArrayList();
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
	private final static char[] IMMUNE_CSS = {};
	private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
	private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '_' };
	private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_SQL = { ' ' };
	private final static char[] IMMUNE_OS = { '-' };
	private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };
	
	
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
        int mixedCount = 1;
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
                        mixedCount++;
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
        if ( foundCount >= 2 && mixedCount > 1 ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        else if ( foundCount >= 2 ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) encoding detected in " + input );
            }
        }
        else if ( mixedCount > 1 ) {
            if ( strict ) {
                throw new IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Mixed encoding ("+ mixedCount +"x) detected in " + input );
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
	 * {@inheritDoc}
	 */
	public String encodeForHTML(String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return htmlCodec.encode( IMMUNE_HTML, input);	    
	 }
	 
	 
	/**
	 * {@inheritDoc}
	 */
	public String encodeForHTMLAttribute(String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return htmlCodec.encode( IMMUNE_HTMLATTR, input);
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForCSS(String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return cssCodec.encode( IMMUNE_CSS, input);
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForJavaScript(String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForVBScript(String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);	    
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String encodeForSQL(Codec codec, String input) {
	    if( input == null ) {
	    	return null;
	    }
	    return codec.encode(IMMUNE_SQL, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForOS(Codec codec, String input) {
	    if( input == null ) {
	    	return null;	
	    }
	    return codec.encode( IMMUNE_OS, input);
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
	    return htmlCodec.encode( IMMUNE_XPATH, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXML(String input) {
	    if( input == null ) {
	    	return null;	
	    }
	    return htmlCodec.encode( IMMUNE_XML, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXMLAttribute(String input) {
	    if( input == null ) {
	    	return null;	
	    }
	    return htmlCodec.encode( IMMUNE_XMLATTR, input);
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
			throw new EncodingException("Encoding failure", "Problem URL encoding input", e);
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

}