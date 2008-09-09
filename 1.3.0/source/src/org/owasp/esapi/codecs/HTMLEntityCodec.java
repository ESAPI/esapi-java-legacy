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
package org.owasp.esapi.codecs;

import java.util.HashMap;

/**
 * Implementation of the Codec interface for HTML entity encoding.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class HTMLEntityCodec implements Codec {
	
	private static HashMap characterToEntityMap;

	private static HashMap entityToCharacterMap;

	public HTMLEntityCodec() {
		initializeMaps();
	}

	public String encode( String input ) {
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			sb.append( encodeCharacter( new Character( input.charAt(i) ) ) );
		}
		return sb.toString();
	}


	public String encodeCharacter( Character c ) {
		String entityName = (String) characterToEntityMap.get(c);
		if (entityName != null) {
			return "&" + entityName + ";";
		}
		return "&#" + (int)c.charValue() + ";";
	}
	
	
	public String decode( String input ) {
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString( input );
		while ( pbs.hasNext() ) {
			Character c = decodeCharacter( pbs );
			if ( c != null ) {
				sb.append( c );
			} else {
				sb.append( pbs.next() );
			}
		}
		return sb.toString();
	}
	
	
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal both with and without semi-colon, upper/lower case:
	 *   &#dddd;
	 *   &#xhhhh;
	 *   &name;
	 */
	public Character decodeCharacter( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '&' ) {
			input.reset();
			return null;
		}
		
		// test for numeric encodings
		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		if ( second.charValue() == '#' ) {
			// handle numbers
			Character c = getNumericEntity( input );
			if ( c != null ) return c;
		} else if ( Character.isLetter( second.charValue() ) ) {
			// handle entities
			input.pushback( second );
			Character c = getNamedEntity( input );
			if ( c != null ) return c;
		}
		input.reset();
		return null;
	}
	
	
	private Character getNumericEntity( PushbackString input ) {
		Character first = input.peek();
		if ( first == null ) return null;

		if ( first.charValue() == 'x' || first.charValue() == 'X' ) {
			input.next();
			return parseHex( input );
		}
		return parseNumber( input );
	}

	
	private Character parseNumber( PushbackString input ) {
		StringBuffer sb = new StringBuffer();
		while( input.hasNext() ) {
			Character c = input.peek();
			
			// if character is a digit then add it on and keep going
			if ( Character.isDigit( c.charValue() ) ) {
				sb.append( c );
				input.next();
				
			// if character is a semi-colon, eat it and quit
			} else if ( c.charValue() == ';' ) {
				input.next();
				break;
				
			// otherwise just quit
			} else {
				break;
			}
		}
		try {
			int i = Integer.parseInt(sb.toString());
			// TODO: in Java 1.5 you can test whether this is a valid code point
			// with Character.isValidCodePoint() et al.
			return new Character( (char)i );
		} catch( NumberFormatException e ) {
			// throw an exception for malformed entity?
			return null;
		}
	}
	
	private Character parseHex( PushbackString input ) {
		StringBuffer sb = new StringBuffer();
		while( input.hasNext() ) {
			Character c = input.peek();
			
			// if character is a hex digit then add it on and keep going
			if ( "0123456789ABCDEFabcdef".indexOf( c.charValue() ) != -1 ) {
				sb.append( c );
				input.next();
				
			// if character is a semi-colon, eat it and quit
			} else if ( c.charValue() == ';' ) {
				input.next();
				break;
				
			// otherwise just quit
			} else {
				break;
			}
		}
		try {
			int i = Integer.parseInt(sb.toString(), 16);
			// TODO: in Java 1.5 you can test whether this is a valid code point
			// with Character.isValidCodePoint() et al.
			return new Character( (char)i );
		} catch( NumberFormatException e ) {
			// throw an exception for malformed entity?
			return null;
		}
	}
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal both with and without semi-colon, upper/lower case:
	 *   &aa;
	 *   &aaa;
	 *   &aaaa;
	 *   &aaaaa;
	 *   &aaaaaa;
	 *   &aaaaaaa;
	 */
	private Character getNamedEntity( PushbackString input ) {
		// search through the rest of the string up to 6 characters
		// System.out.println( "REM: " + input.remainder() );
		StringBuffer possible = new StringBuffer();
		int len = Math.min( input.remainder().length(), 7 );
		for ( int i=0; i<len; i++ ) {
			possible.append( Character.toLowerCase(input.next().charValue()) );
			// System.out.println( "             >> " + possible );
			Character entity = (Character) entityToCharacterMap.get(possible.toString());
			if ( entity != null ) {
				// eat any trailing semicolons
				if ( input.peek( ';') ) {
					input.next();
				}
				return entity;
			}
		}
		return null;
	}

	
	public static void main( String[] args ) {
		HTMLEntityCodec codec = new HTMLEntityCodec();
		String test = "&lt";
		// String test = "&#x25 &#X3c;script&#x3e; &#X3cscript&#x3e &#X3Cscript&#x000000000000000000000000000003e &#000000060script&#000000062 &#60;script&#62; &#60script&#62";
		System.out.println( "Original: " + test );
		System.out.println( "Decoded: " + codec.decode( test ) );
	}
	
		
	private void initializeMaps() {
		String[] entityNames = { "quot"
		/* 34 : quotation mark */, "amp"
		/* 38 : ampersand */, "lt"
		/* 60 : less-than sign */, "gt"
		/* 62 : greater-than sign */, "nbsp"
		/* 160 : no-break space */, "iexcl"
		/* 161 : inverted exclamation mark */, "cent"
		/* 162 : cent sign */, "pound"
		/* 163 : pound sign */, "curren"
		/* 164 : currency sign */, "yen"
		/* 165 : yen sign */, "brvbar"
		/* 166 : broken bar */, "sect"
		/* 167 : section sign */, "uml"
		/* 168 : diaeresis */, "copy"
		/* 169 : copyright sign */, "ordf"
		/* 170 : feminine ordinal indicator */, "laquo"
		/* 171 : left-pointing double angle quotation mark */, "not"
		/* 172 : not sign */, "shy"
		/* 173 : soft hyphen */, "reg"
		/* 174 : registered sign */, "macr"
		/* 175 : macron */, "deg"
		/* 176 : degree sign */, "plusmn"
		/* 177 : plus-minus sign */, "sup2"
		/* 178 : superscript two */, "sup3"
		/* 179 : superscript three */, "acute"
		/* 180 : acute accent */, "micro"
		/* 181 : micro sign */, "para"
		/* 182 : pilcrow sign */, "middot"
		/* 183 : middle dot */, "cedil"
		/* 184 : cedilla */, "sup1"
		/* 185 : superscript one */, "ordm"
		/* 186 : masculine ordinal indicator */, "raquo"
		/* 187 : right-pointing double angle quotation mark */, "frac14"
		/* 188 : vulgar fraction one quarter */, "frac12"
		/* 189 : vulgar fraction one half */, "frac34"
		/* 190 : vulgar fraction three quarters */, "iquest"
		/* 191 : inverted question mark */, "Agrave"
		/* 192 : Latin capital letter a with grave */, "Aacute"
		/* 193 : Latin capital letter a with acute */, "Acirc"
		/* 194 : Latin capital letter a with circumflex */, "Atilde"
		/* 195 : Latin capital letter a with tilde */, "Auml"
		/* 196 : Latin capital letter a with diaeresis */, "Aring"
		/* 197 : Latin capital letter a with ring above */, "AElig"
		/* 198 : Latin capital letter ae */, "Ccedil"
		/* 199 : Latin capital letter c with cedilla */, "Egrave"
		/* 200 : Latin capital letter e with grave */, "Eacute"
		/* 201 : Latin capital letter e with acute */, "Ecirc"
		/* 202 : Latin capital letter e with circumflex */, "Euml"
		/* 203 : Latin capital letter e with diaeresis */, "Igrave"
		/* 204 : Latin capital letter i with grave */, "Iacute"
		/* 205 : Latin capital letter i with acute */, "Icirc"
		/* 206 : Latin capital letter i with circumflex */, "Iuml"
		/* 207 : Latin capital letter i with diaeresis */, "ETH"
		/* 208 : Latin capital letter eth */, "Ntilde"
		/* 209 : Latin capital letter n with tilde */, "Ograve"
		/* 210 : Latin capital letter o with grave */, "Oacute"
		/* 211 : Latin capital letter o with acute */, "Ocirc"
		/* 212 : Latin capital letter o with circumflex */, "Otilde"
		/* 213 : Latin capital letter o with tilde */, "Ouml"
		/* 214 : Latin capital letter o with diaeresis */, "times"
		/* 215 : multiplication sign */, "Oslash"
		/* 216 : Latin capital letter o with stroke */, "Ugrave"
		/* 217 : Latin capital letter u with grave */, "Uacute"
		/* 218 : Latin capital letter u with acute */, "Ucirc"
		/* 219 : Latin capital letter u with circumflex */, "Uuml"
		/* 220 : Latin capital letter u with diaeresis */, "Yacute"
		/* 221 : Latin capital letter y with acute */, "THORN"
		/* 222 : Latin capital letter thorn */, "szlig"
		/* 223 : Latin small letter sharp s, German Eszett */, "agrave"
		/* 224 : Latin small letter a with grave */, "aacute"
		/* 225 : Latin small letter a with acute */, "acirc"
		/* 226 : Latin small letter a with circumflex */, "atilde"
		/* 227 : Latin small letter a with tilde */, "auml"
		/* 228 : Latin small letter a with diaeresis */, "aring"
		/* 229 : Latin small letter a with ring above */, "aelig"
		/* 230 : Latin lowercase ligature ae */, "ccedil"
		/* 231 : Latin small letter c with cedilla */, "egrave"
		/* 232 : Latin small letter e with grave */, "eacute"
		/* 233 : Latin small letter e with acute */, "ecirc"
		/* 234 : Latin small letter e with circumflex */, "euml"
		/* 235 : Latin small letter e with diaeresis */, "igrave"
		/* 236 : Latin small letter i with grave */, "iacute"
		/* 237 : Latin small letter i with acute */, "icirc"
		/* 238 : Latin small letter i with circumflex */, "iuml"
		/* 239 : Latin small letter i with diaeresis */, "eth"
		/* 240 : Latin small letter eth */, "ntilde"
		/* 241 : Latin small letter n with tilde */, "ograve"
		/* 242 : Latin small letter o with grave */, "oacute"
		/* 243 : Latin small letter o with acute */, "ocirc"
		/* 244 : Latin small letter o with circumflex */, "otilde"
		/* 245 : Latin small letter o with tilde */, "ouml"
		/* 246 : Latin small letter o with diaeresis */, "divide"
		/* 247 : division sign */, "oslash"
		/* 248 : Latin small letter o with stroke */, "ugrave"
		/* 249 : Latin small letter u with grave */, "uacute"
		/* 250 : Latin small letter u with acute */, "ucirc"
		/* 251 : Latin small letter u with circumflex */, "uuml"
		/* 252 : Latin small letter u with diaeresis */, "yacute"
		/* 253 : Latin small letter y with acute */, "thorn"
		/* 254 : Latin small letter thorn */, "yuml"
		/* 255 : Latin small letter y with diaeresis */, "OElig"
		/* 338 : Latin capital ligature oe */, "oelig"
		/* 339 : Latin small ligature oe */, "Scaron"
		/* 352 : Latin capital letter s with caron */, "scaron"
		/* 353 : Latin small letter s with caron */, "Yuml"
		/* 376 : Latin capital letter y with diaeresis */, "fnof"
		/* 402 : Latin small letter f with hook */, "circ"
		/* 710 : modifier letter circumflex accent */, "tilde"
		/* 732 : small tilde */, "Alpha"
		/* 913 : Greek capital letter alpha */, "Beta"
		/* 914 : Greek capital letter beta */, "Gamma"
		/* 915 : Greek capital letter gamma */, "Delta"
		/* 916 : Greek capital letter delta */, "Epsilon"
		/* 917 : Greek capital letter epsilon */, "Zeta"
		/* 918 : Greek capital letter zeta */, "Eta"
		/* 919 : Greek capital letter eta */, "Theta"
		/* 920 : Greek capital letter theta */, "Iota"
		/* 921 : Greek capital letter iota */, "Kappa"
		/* 922 : Greek capital letter kappa */, "Lambda"
		/* 923 : Greek capital letter lambda */, "Mu"
		/* 924 : Greek capital letter mu */, "Nu"
		/* 925 : Greek capital letter nu */, "Xi"
		/* 926 : Greek capital letter xi */, "Omicron"
		/* 927 : Greek capital letter omicron */, "Pi"
		/* 928 : Greek capital letter pi */, "Rho"
		/* 929 : Greek capital letter rho */, "Sigma"
		/* 931 : Greek capital letter sigma */, "Tau"
		/* 932 : Greek capital letter tau */, "Upsilon"
		/* 933 : Greek capital letter upsilon */, "Phi"
		/* 934 : Greek capital letter phi */, "Chi"
		/* 935 : Greek capital letter chi */, "Psi"
		/* 936 : Greek capital letter psi */, "Omega"
		/* 937 : Greek capital letter omega */, "alpha"
		/* 945 : Greek small letter alpha */, "beta"
		/* 946 : Greek small letter beta */, "gamma"
		/* 947 : Greek small letter gamma */, "delta"
		/* 948 : Greek small letter delta */, "epsilon"
		/* 949 : Greek small letter epsilon */, "zeta"
		/* 950 : Greek small letter zeta */, "eta"
		/* 951 : Greek small letter eta */, "theta"
		/* 952 : Greek small letter theta */, "iota"
		/* 953 : Greek small letter iota */, "kappa"
		/* 954 : Greek small letter kappa */, "lambda"
		/* 955 : Greek small letter lambda */, "mu"
		/* 956 : Greek small letter mu */, "nu"
		/* 957 : Greek small letter nu */, "xi"
		/* 958 : Greek small letter xi */, "omicron"
		/* 959 : Greek small letter omicron */, "pi"
		/* 960 : Greek small letter pi */, "rho"
		/* 961 : Greek small letter rho */, "sigmaf"
		/* 962 : Greek small letter final sigma */, "sigma"
		/* 963 : Greek small letter sigma */, "tau"
		/* 964 : Greek small letter tau */, "upsilon"
		/* 965 : Greek small letter upsilon */, "phi"
		/* 966 : Greek small letter phi */, "chi"
		/* 967 : Greek small letter chi */, "psi"
		/* 968 : Greek small letter psi */, "omega"
		/* 969 : Greek small letter omega */, "thetasym"
		/* 977 : Greek theta symbol */, "upsih"
		/* 978 : Greek upsilon with hook symbol */, "piv"
		/* 982 : Greek pi symbol */, "ensp"
		/* 8194 : en space */, "emsp"
		/* 8195 : em space */, "thinsp"
		/* 8201 : thin space */, "zwnj"
		/* 8204 : zero width non-joiner */, "zwj"
		/* 8205 : zero width joiner */, "lrm"
		/* 8206 : left-to-right mark */, "rlm"
		/* 8207 : right-to-left mark */, "ndash"
		/* 8211 : en dash */, "mdash"
		/* 8212 : em dash */, "lsquo"
		/* 8216 : left single quotation mark */, "rsquo"
		/* 8217 : right single quotation mark */, "sbquo"
		/* 8218 : single low-9 quotation mark */, "ldquo"
		/* 8220 : left double quotation mark */, "rdquo"
		/* 8221 : right double quotation mark */, "bdquo"
		/* 8222 : double low-9 quotation mark */, "dagger"
		/* 8224 : dagger */, "Dagger"
		/* 8225 : double dagger */, "bull"
		/* 8226 : bullet */, "hellip"
		/* 8230 : horizontal ellipsis */, "permil"
		/* 8240 : per mille sign */, "prime"
		/* 8242 : prime */, "Prime"
		/* 8243 : double prime */, "lsaquo"
		/* 8249 : single left-pointing angle quotation mark */, "rsaquo"
		/* 8250 : single right-pointing angle quotation mark */, "oline"
		/* 8254 : overline */, "frasl"
		/* 8260 : fraction slash */, "euro"
		/* 8364 : euro sign */, "image"
		/* 8465 : black-letter capital i */, "weierp"
		/* 8472 : script capital p, Weierstrass p */, "real"
		/* 8476 : black-letter capital r */, "trade"
		/* 8482 : trademark sign */, "alefsym"
		/* 8501 : alef symbol */, "larr"
		/* 8592 : leftwards arrow */, "uarr"
		/* 8593 : upwards arrow */, "rarr"
		/* 8594 : rightwards arrow */, "darr"
		/* 8595 : downwards arrow */, "harr"
		/* 8596 : left right arrow */, "crarr"
		/* 8629 : downwards arrow with corner leftwards */, "lArr"
		/* 8656 : leftwards double arrow */, "uArr"
		/* 8657 : upwards double arrow */, "rArr"
		/* 8658 : rightwards double arrow */, "dArr"
		/* 8659 : downwards double arrow */, "hArr"
		/* 8660 : left right double arrow */, "forall"
		/* 8704 : for all */, "part"
		/* 8706 : partial differential */, "exist"
		/* 8707 : there exists */, "empty"
		/* 8709 : empty set */, "nabla"
		/* 8711 : nabla */, "isin"
		/* 8712 : element of */, "notin"
		/* 8713 : not an element of */, "ni"
		/* 8715 : contains as member */, "prod"
		/* 8719 : n-ary product */, "sum"
		/* 8721 : n-ary summation */, "minus"
		/* 8722 : minus sign */, "lowast"
		/* 8727 : asterisk operator */, "radic"
		/* 8730 : square root */, "prop"
		/* 8733 : proportional to */, "infin"
		/* 8734 : infinity */, "ang"
		/* 8736 : angle */, "and"
		/* 8743 : logical and */, "or"
		/* 8744 : logical or */, "cap"
		/* 8745 : intersection */, "cup"
		/* 8746 : union */, "int"
		/* 8747 : integral */, "there4"
		/* 8756 : therefore */, "sim"
		/* 8764 : tilde operator */, "cong"
		/* 8773 : congruent to */, "asymp"
		/* 8776 : almost equal to */, "ne"
		/* 8800 : not equal to */, "equiv"
		/* 8801 : identical to, equivalent to */, "le"
		/* 8804 : less-than or equal to */, "ge"
		/* 8805 : greater-than or equal to */, "sub"
		/* 8834 : subset of */, "sup"
		/* 8835 : superset of */, "nsub"
		/* 8836 : not a subset of */, "sube"
		/* 8838 : subset of or equal to */, "supe"
		/* 8839 : superset of or equal to */, "oplus"
		/* 8853 : circled plus */, "otimes"
		/* 8855 : circled times */, "perp"
		/* 8869 : up tack */, "sdot"
		/* 8901 : dot operator */, "lceil"
		/* 8968 : left ceiling */, "rceil"
		/* 8969 : right ceiling */, "lfloor"
		/* 8970 : left floor */, "rfloor"
		/* 8971 : right floor */, "lang"
		/* 9001 : left-pointing angle bracket */, "rang"
		/* 9002 : right-pointing angle bracket */, "loz"
		/* 9674 : lozenge */, "spades"
		/* 9824 : black spade suit */, "clubs"
		/* 9827 : black club suit */, "hearts"
		/* 9829 : black heart suit */, "diams"
		/* 9830 : black diamond suit */, };

		char[] entityValues = { 34
		/* &quot; : quotation mark */, 38
		/* &amp; : ampersand */, 60
		/* &lt; : less-than sign */, 62
		/* &gt; : greater-than sign */, 160
		/* &nbsp; : no-break space */, 161
		/* &iexcl; : inverted exclamation mark */, 162
		/* &cent; : cent sign */, 163
		/* &pound; : pound sign */, 164
		/* &curren; : currency sign */, 165
		/* &yen; : yen sign */, 166
		/* &brvbar; : broken bar */, 167
		/* &sect; : section sign */, 168
		/* &uml; : diaeresis */, 169
		/* &copy; : copyright sign */, 170
		/* &ordf; : feminine ordinal indicator */, 171
		/* &laquo; : left-pointing double angle quotation mark */, 172
		/* &not; : not sign */, 173
		/* &shy; : soft hyphen */, 174
		/* &reg; : registered sign */, 175
		/* &macr; : macron */, 176
		/* &deg; : degree sign */, 177
		/* &plusmn; : plus-minus sign */, 178
		/* &sup2; : superscript two */, 179
		/* &sup3; : superscript three */, 180
		/* &acute; : acute accent */, 181
		/* &micro; : micro sign */, 182
		/* &para; : pilcrow sign */, 183
		/* &middot; : middle dot */, 184
		/* &cedil; : cedilla */, 185
		/* &sup1; : superscript one */, 186
		/* &ordm; : masculine ordinal indicator */, 187
		/* &raquo; : right-pointing double angle quotation mark */, 188
		/* &frac14; : vulgar fraction one quarter */, 189
		/* &frac12; : vulgar fraction one half */, 190
		/* &frac34; : vulgar fraction three quarters */, 191
		/* &iquest; : inverted question mark */, 192
		/* &Agrave; : Latin capital letter a with grave */, 193
		/* &Aacute; : Latin capital letter a with acute */, 194
		/* &Acirc; : Latin capital letter a with circumflex */, 195
		/* &Atilde; : Latin capital letter a with tilde */, 196
		/* &Auml; : Latin capital letter a with diaeresis */, 197
		/* &Aring; : Latin capital letter a with ring above */, 198
		/* &AElig; : Latin capital letter ae */, 199
		/* &Ccedil; : Latin capital letter c with cedilla */, 200
		/* &Egrave; : Latin capital letter e with grave */, 201
		/* &Eacute; : Latin capital letter e with acute */, 202
		/* &Ecirc; : Latin capital letter e with circumflex */, 203
		/* &Euml; : Latin capital letter e with diaeresis */, 204
		/* &Igrave; : Latin capital letter i with grave */, 205
		/* &Iacute; : Latin capital letter i with acute */, 206
		/* &Icirc; : Latin capital letter i with circumflex */, 207
		/* &Iuml; : Latin capital letter i with diaeresis */, 208
		/* &ETH; : Latin capital letter eth */, 209
		/* &Ntilde; : Latin capital letter n with tilde */, 210
		/* &Ograve; : Latin capital letter o with grave */, 211
		/* &Oacute; : Latin capital letter o with acute */, 212
		/* &Ocirc; : Latin capital letter o with circumflex */, 213
		/* &Otilde; : Latin capital letter o with tilde */, 214
		/* &Ouml; : Latin capital letter o with diaeresis */, 215
		/* &times; : multiplication sign */, 216
		/* &Oslash; : Latin capital letter o with stroke */, 217
		/* &Ugrave; : Latin capital letter u with grave */, 218
		/* &Uacute; : Latin capital letter u with acute */, 219
		/* &Ucirc; : Latin capital letter u with circumflex */, 220
		/* &Uuml; : Latin capital letter u with diaeresis */, 221
		/* &Yacute; : Latin capital letter y with acute */, 222
		/* &THORN; : Latin capital letter thorn */, 223
		/* &szlig; : Latin small letter sharp s, German Eszett */, 224
		/* &agrave; : Latin small letter a with grave */, 225
		/* &aacute; : Latin small letter a with acute */, 226
		/* &acirc; : Latin small letter a with circumflex */, 227
		/* &atilde; : Latin small letter a with tilde */, 228
		/* &auml; : Latin small letter a with diaeresis */, 229
		/* &aring; : Latin small letter a with ring above */, 230
		/* &aelig; : Latin lowercase ligature ae */, 231
		/* &ccedil; : Latin small letter c with cedilla */, 232
		/* &egrave; : Latin small letter e with grave */, 233
		/* &eacute; : Latin small letter e with acute */, 234
		/* &ecirc; : Latin small letter e with circumflex */, 235
		/* &euml; : Latin small letter e with diaeresis */, 236
		/* &igrave; : Latin small letter i with grave */, 237
		/* &iacute; : Latin small letter i with acute */, 238
		/* &icirc; : Latin small letter i with circumflex */, 239
		/* &iuml; : Latin small letter i with diaeresis */, 240
		/* &eth; : Latin small letter eth */, 241
		/* &ntilde; : Latin small letter n with tilde */, 242
		/* &ograve; : Latin small letter o with grave */, 243
		/* &oacute; : Latin small letter o with acute */, 244
		/* &ocirc; : Latin small letter o with circumflex */, 245
		/* &otilde; : Latin small letter o with tilde */, 246
		/* &ouml; : Latin small letter o with diaeresis */, 247
		/* &divide; : division sign */, 248
		/* &oslash; : Latin small letter o with stroke */, 249
		/* &ugrave; : Latin small letter u with grave */, 250
		/* &uacute; : Latin small letter u with acute */, 251
		/* &ucirc; : Latin small letter u with circumflex */, 252
		/* &uuml; : Latin small letter u with diaeresis */, 253
		/* &yacute; : Latin small letter y with acute */, 254
		/* &thorn; : Latin small letter thorn */, 255
		/* &yuml; : Latin small letter y with diaeresis */, 338
		/* &OElig; : Latin capital ligature oe */, 339
		/* &oelig; : Latin small ligature oe */, 352
		/* &Scaron; : Latin capital letter s with caron */, 353
		/* &scaron; : Latin small letter s with caron */, 376
		/* &Yuml; : Latin capital letter y with diaeresis */, 402
		/* &fnof; : Latin small letter f with hook */, 710
		/* &circ; : modifier letter circumflex accent */, 732
		/* &tilde; : small tilde */, 913
		/* &Alpha; : Greek capital letter alpha */, 914
		/* &Beta; : Greek capital letter beta */, 915
		/* &Gamma; : Greek capital letter gamma */, 916
		/* &Delta; : Greek capital letter delta */, 917
		/* &Epsilon; : Greek capital letter epsilon */, 918
		/* &Zeta; : Greek capital letter zeta */, 919
		/* &Eta; : Greek capital letter eta */, 920
		/* &Theta; : Greek capital letter theta */, 921
		/* &Iota; : Greek capital letter iota */, 922
		/* &Kappa; : Greek capital letter kappa */, 923
		/* &Lambda; : Greek capital letter lambda */, 924
		/* &Mu; : Greek capital letter mu */, 925
		/* &Nu; : Greek capital letter nu */, 926
		/* &Xi; : Greek capital letter xi */, 927
		/* &Omicron; : Greek capital letter omicron */, 928
		/* &Pi; : Greek capital letter pi */, 929
		/* &Rho; : Greek capital letter rho */, 931
		/* &Sigma; : Greek capital letter sigma */, 932
		/* &Tau; : Greek capital letter tau */, 933
		/* &Upsilon; : Greek capital letter upsilon */, 934
		/* &Phi; : Greek capital letter phi */, 935
		/* &Chi; : Greek capital letter chi */, 936
		/* &Psi; : Greek capital letter psi */, 937
		/* &Omega; : Greek capital letter omega */, 945
		/* &alpha; : Greek small letter alpha */, 946
		/* &beta; : Greek small letter beta */, 947
		/* &gamma; : Greek small letter gamma */, 948
		/* &delta; : Greek small letter delta */, 949
		/* &epsilon; : Greek small letter epsilon */, 950
		/* &zeta; : Greek small letter zeta */, 951
		/* &eta; : Greek small letter eta */, 952
		/* &theta; : Greek small letter theta */, 953
		/* &iota; : Greek small letter iota */, 954
		/* &kappa; : Greek small letter kappa */, 955
		/* &lambda; : Greek small letter lambda */, 956
		/* &mu; : Greek small letter mu */, 957
		/* &nu; : Greek small letter nu */, 958
		/* &xi; : Greek small letter xi */, 959
		/* &omicron; : Greek small letter omicron */, 960
		/* &pi; : Greek small letter pi */, 961
		/* &rho; : Greek small letter rho */, 962
		/* &sigmaf; : Greek small letter final sigma */, 963
		/* &sigma; : Greek small letter sigma */, 964
		/* &tau; : Greek small letter tau */, 965
		/* &upsilon; : Greek small letter upsilon */, 966
		/* &phi; : Greek small letter phi */, 967
		/* &chi; : Greek small letter chi */, 968
		/* &psi; : Greek small letter psi */, 969
		/* &omega; : Greek small letter omega */, 977
		/* &thetasym; : Greek theta symbol */, 978
		/* &upsih; : Greek upsilon with hook symbol */, 982
		/* &piv; : Greek pi symbol */, 8194
		/* &ensp; : en space */, 8195
		/* &emsp; : em space */, 8201
		/* &thinsp; : thin space */, 8204
		/* &zwnj; : zero width non-joiner */, 8205
		/* &zwj; : zero width joiner */, 8206
		/* &lrm; : left-to-right mark */, 8207
		/* &rlm; : right-to-left mark */, 8211
		/* &ndash; : en dash */, 8212
		/* &mdash; : em dash */, 8216
		/* &lsquo; : left single quotation mark */, 8217
		/* &rsquo; : right single quotation mark */, 8218
		/* &sbquo; : single low-9 quotation mark */, 8220
		/* &ldquo; : left double quotation mark */, 8221
		/* &rdquo; : right double quotation mark */, 8222
		/* &bdquo; : double low-9 quotation mark */, 8224
		/* &dagger; : dagger */, 8225
		/* &Dagger; : double dagger */, 8226
		/* &bull; : bullet */, 8230
		/* &hellip; : horizontal ellipsis */, 8240
		/* &permil; : per mille sign */, 8242
		/* &prime; : prime */, 8243
		/* &Prime; : double prime */, 8249
		/* &lsaquo; : single left-pointing angle quotation mark */, 8250
		/* &rsaquo; : single right-pointing angle quotation mark */, 8254
		/* &oline; : overline */, 8260
		/* &frasl; : fraction slash */, 8364
		/* &euro; : euro sign */, 8465
		/* &image; : black-letter capital i */, 8472
		/* &weierp; : script capital p, Weierstrass p */, 8476
		/* &real; : black-letter capital r */, 8482
		/* &trade; : trademark sign */, 8501
		/* &alefsym; : alef symbol */, 8592
		/* &larr; : leftwards arrow */, 8593
		/* &uarr; : upwards arrow */, 8594
		/* &rarr; : rightwards arrow */, 8595
		/* &darr; : downwards arrow */, 8596
		/* &harr; : left right arrow */, 8629
		/* &crarr; : downwards arrow with corner leftwards */, 8656
		/* &lArr; : leftwards double arrow */, 8657
		/* &uArr; : upwards double arrow */, 8658
		/* &rArr; : rightwards double arrow */, 8659
		/* &dArr; : downwards double arrow */, 8660
		/* &hArr; : left right double arrow */, 8704
		/* &forall; : for all */, 8706
		/* &part; : partial differential */, 8707
		/* &exist; : there exists */, 8709
		/* &empty; : empty set */, 8711
		/* &nabla; : nabla */, 8712
		/* &isin; : element of */, 8713
		/* &notin; : not an element of */, 8715
		/* &ni; : contains as member */, 8719
		/* &prod; : n-ary product */, 8721
		/* &sum; : n-ary summation */, 8722
		/* &minus; : minus sign */, 8727
		/* &lowast; : asterisk operator */, 8730
		/* &radic; : square root */, 8733
		/* &prop; : proportional to */, 8734
		/* &infin; : infinity */, 8736
		/* &ang; : angle */, 8743
		/* &and; : logical and */, 8744
		/* &or; : logical or */, 8745
		/* &cap; : intersection */, 8746
		/* &cup; : union */, 8747
		/* &int; : integral */, 8756
		/* &there4; : therefore */, 8764
		/* &sim; : tilde operator */, 8773
		/* &cong; : congruent to */, 8776
		/* &asymp; : almost equal to */, 8800
		/* &ne; : not equal to */, 8801
		/* &equiv; : identical to, equivalent to */, 8804
		/* &le; : less-than or equal to */, 8805
		/* &ge; : greater-than or equal to */, 8834
		/* &sub; : subset of */, 8835
		/* &sup; : superset of */, 8836
		/* &nsub; : not a subset of */, 8838
		/* &sube; : subset of or equal to */, 8839
		/* &supe; : superset of or equal to */, 8853
		/* &oplus; : circled plus */, 8855
		/* &otimes; : circled times */, 8869
		/* &perp; : up tack */, 8901
		/* &sdot; : dot operator */, 8968
		/* &lceil; : left ceiling */, 8969
		/* &rceil; : right ceiling */, 8970
		/* &lfloor; : left floor */, 8971
		/* &rfloor; : right floor */, 9001
		/* &lang; : left-pointing angle bracket */, 9002
		/* &rang; : right-pointing angle bracket */, 9674
		/* &loz; : lozenge */, 9824
		/* &spades; : black spade suit */, 9827
		/* &clubs; : black club suit */, 9829
		/* &hearts; : black heart suit */, 9830
		/* &diams; : black diamond suit */, };
		characterToEntityMap = new HashMap(entityNames.length);
		entityToCharacterMap = new HashMap(entityValues.length);
		for (int i = 0; i < entityNames.length; i++) {
			String e = entityNames[i];
			Character c = new Character(entityValues[i]);
			entityToCharacterMap.put(e, c);
			characterToEntityMap.put(c, e);
		}
	}
	
}