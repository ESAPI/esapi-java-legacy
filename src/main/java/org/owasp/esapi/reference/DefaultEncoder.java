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
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.codecs.Base64;
import org.owasp.esapi.codecs.CSSCodec;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.JavaScriptCodec;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.VBScriptCodec;
import org.owasp.esapi.codecs.XMLEntityCodec;
import org.owasp.esapi.codecs.JSONCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.errors.NotConfiguredByDefaultException;

import static org.owasp.esapi.PropNames.ACCEPTED_UNSAFE_METHOD_NAMES;
import static  org.owasp.esapi.PropNames.ACCEPTED_UNSAFE_METHODS_JUSTIFICATION;


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
public class DefaultEncoder implements Encoder {

    private static volatile Encoder singletonInstance;

    public static Encoder getInstance() {
        if ( singletonInstance == null ) {
            synchronized ( DefaultEncoder.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new DefaultEncoder();
                }
            }
        }
        return singletonInstance;
    }

    // Codecs
    private List codecs = new ArrayList();
    private HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
    private XMLEntityCodec xmlCodec = new XMLEntityCodec();
    private PercentCodec percentCodec = new PercentCodec();
    private JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
    private VBScriptCodec vbScriptCodec = new VBScriptCodec();
    private CSSCodec cssCodec = new CSSCodec();
    private JSONCodec jsonCodec = new JSONCodec();

    private final Logger logger = ESAPI.getLogger("Encoder");

    /**
     *  Character sets that define characters (in addition to alphanumerics) that are
     * immune from encoding in various formats
     */
    private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_CSS = { '#' };
    private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_SQL = { ' ' };
    private final static char[] IMMUNE_OS = { '-' };
    private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_JSON = { };


    /**
     * Instantiates a new {@code DefaultEncoder} based on the property {@code Encoder.DefaultCodecList}
     * from the {@code ESAPI.properties} file.
     */
    private DefaultEncoder() {
        this( ESAPI.securityConfiguration().getDefaultCanonicalizationCodecs() );
    }

    /**
     * Instantiates a new {@code DefaultEncoder} based on the specified list of
     * codec names. Unqualified codec names are assumed to belong to the package
     * "org.owasp.esapi.codecs".
     */
    public DefaultEncoder( List<String> codecNames ) {
        for ( String clazz : codecNames ) {
            try {
                if ( clazz.indexOf( '.' ) == -1 ) clazz = "org.owasp.esapi.codecs." + clazz;
                codecs.add( Class.forName( clazz ).newInstance() );
            } catch ( Exception e ) {
                logger.warning( Logger.EVENT_FAILURE, "Codec " + clazz + " listed in ESAPI.properties not on classpath" );
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input ) {
        if ( input == null ) {
            return null;
        }

        // Issue 231 - These are reverse boolean logic in the Encoder interface, so we need to invert these values - CS
        return canonicalize(input,
                            !ESAPI.securityConfiguration().getAllowMultipleEncoding(),
                            !ESAPI.securityConfiguration().getAllowMixedEncoding() );
    }


    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input, boolean strict) {
        return canonicalize(input, strict, strict);
    }


    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input, boolean restrictMultiple, boolean restrictMixed ) {
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
            if ( restrictMultiple || restrictMixed ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        else if ( foundCount >= 2 ) {
            if ( restrictMultiple ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) encoding detected in " + input );
            }
        }
        else if ( mixedCount > 1 ) {
            if ( restrictMixed ) {
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
    public String encodeForHTML(String input) {
        if( input == null ) {
            return null;
        }
        return htmlCodec.encode( IMMUNE_HTML, input);
     }

    /**
     * {@inheritDoc}
     */
    public String decodeForHTML(String input) {

        if( input == null ) {
            return null;
        }
        return htmlCodec.decode( input);
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

    ///////////////////////////////////////////////////////////////////////
    // TODO - Move this method to some utility class (where?) when we
    //        are ready to use it on other methods than just encodeForSQL.
    //
    //        At that time, also move the method ESAPI.isMethodExplicityEnabled
    //        to the same utility class.
    /**
     * Utility class to throw {@code NotConfiguredByDefaultException} if the
     * specified method name is not enabled by default.
     *
     * @param fullyQualifiedMethodName is the method name that we are checkig if
     *                                 enabled in ESAPI.properties.
     * @param customAuditMsg is a audit message to log and use in exceptions. If
     *                       this value passed in is {@code null} or the string
     *                       "&lt;default&gt;", then a canned message is used to
     *                       compose the error message.
     * @param seeAlso is a string that provides additional reference for context
     *                such as a CVE ID, GHAS Security Advisory, or ESAPI Security Bulletin.
     * @throws NotConfiguredByDefaultException if the specified method name is
     *                not listed in the property <b>ESAPI.dangerouslyAllowUnsafeMethods.methodNames</b>
     *                in the <b>ESAPI.properties</b> file.
     */
    private void ensureDangerousMethodExplicitlyEnabled(String fullyQualifiedMethodName,
                                                        String customAuditMsg,
                                                        String seeAlso) {

        String auditMsg = null;
        if ( customAuditMsg == null || customAuditMsg.equalsIgnoreCase("<default>") ) {
            // Special case. Compose an audit message from a canned template.
            // TODO: Null / empty check for 'seeAlso'.
            auditMsg = "SIEM ALERT: Method '" + fullyQualifiedMethodName + "' has been invoked despite having credible " +
                       "security concerns; for additional details, see " + seeAlso + ".";
        } else {
            auditMsg = customAuditMsg;  // Use the custom audit message
        }
 
        if ( ! ESAPI.isMethodExplicityEnabled( fullyQualifiedMethodName ) ) {
            throw new NotConfiguredByDefaultException( "Method not explicitly enabled in property " +
                                                        ACCEPTED_UNSAFE_METHOD_NAMES + "; " + auditMsg );
        } else {
            String justification = null;
            try {
                // This throws a ConfigurationException (rather than returning null if
                // the property name is not found so we need to handle that.
                justification = ESAPI.securityConfiguration().getStringProp( ACCEPTED_UNSAFE_METHODS_JUSTIFICATION );
            } catch ( ConfigurationException cex ) {
                logger.debug( Logger.EVENT_FAILURE, "Property " + ACCEPTED_UNSAFE_METHODS_JUSTIFICATION + " not found.");
                justification = "None";
            }

            if ( justification == null || justification.trim().isEmpty() ) {
                justification = "None";
            }
            logger.warning( Logger.SECURITY_FAILURE, auditMsg + " Provided justification: " + justification );
        }
        return;
    }


    /**
     * {@inheritDoc}
     *
     * @deprecated  This method is considered dangerous and not easily made safe and thus under strong
     *              consideration to be removed within 1 years time after the 2.7.0.0 release. Please
     *              see the referenced ESAPI Security Bulletin #13 for further details.
     */
    @Deprecated
    public String encodeForSQL(Codec codec, String input) {

        // This will throw if this method is not explicitly enabled in ESAPI.properties.
        ensureDangerousMethodExplicitlyEnabled( DefaultEncoder.class.getName() + ".encodeForSQL",
                                                "<default>",
                                                "see CVE-2025-5878 and ESAPI Security Bulletin #13 for details" );

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
        return encodeForLDAP(input, true);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForLDAP(String input, boolean encodeWildcards) {
        if( input == null ) {
            return null;
        }
        // TODO: replace with LDAP codec
        StringBuilder sb = new StringBuilder();
        // According to Microsoft docs [1,2], the forward slash ('/') MUST be escaped.
        // According to RFC 4515 Section 3 [3], the forward slash (and other characters) MAY be escaped.
        // Since Microsoft is a MUST, escape forward slash for all implementations. Also see discussion at [4].
        // Characters above 0x7F are converted to UTF-8 and then hex encoded in the default case.
        // [1] https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
        // [2] https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
        // [3] https://tools.ietf.org/search/rfc4515#section-3
        // [4] https://lists.openldap.org/hyperkitty/list/openldap-technical@openldap.org/thread/3QPDDLO356ONSJM3JUKD7NMPOOIKIQ5T/
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '/':
                    sb.append("\\2f");
                    break;
                case '*':
                    if (encodeWildcards) {
                        sb.append("\\2a");
                    }
                    else {
                        sb.append(c);
                    }

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
                    if (c >= 0x80) {
                        try {
                            final byte[] u = String.valueOf(c).getBytes("UTF-8");
                            for (byte b : u) {
                                sb.append(String.format("\\%02x", b));
                            }
                        } catch (UnsupportedEncodingException ex) {
                            // UTF-8 is always supported
                        }
                    } else {
                        sb.append(c);
                    }
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
        StringBuilder sb = new StringBuilder();
        if ((input.length() > 0) && ((input.charAt(0) == ' ') || (input.charAt(0) == '#'))) {
            sb.append('\\'); // add the leading backslash if needed
        }
        // See discussion of forward slash ('/') in encodeForLDAP()
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
            case '\0':
                sb.append("\\00");
                break;
            case '\\':
                sb.append("\\\\");
                break;
            case '/':
                sb.append("\\/");
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
                if (c >= 0x80) {
                    try {
                        final byte[] u = String.valueOf(c).getBytes("UTF-8");
                        for (byte b : u) {
                            sb.append(String.format("\\%02x", b));
                        }
                    } catch (UnsupportedEncodingException ex) {
                        // UTF-8 is always supported
                    }
                } else {
                    sb.append(c);
                }
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
        return xmlCodec.encode( IMMUNE_XML, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForXMLAttribute(String input) {
        if( input == null ) {
            return null;
        }
        return xmlCodec.encode( IMMUNE_XMLATTR, input);
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
            throw new EncodingException("Encoding failure", "Character encoding not supported", ex);
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
            throw new EncodingException("Decoding failed", "Character encoding not supported", ex);
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
     * {@inheritDoc}
     *
     * This will extract each piece of a URI according to parse zone as specified in <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC-3986</a> section 3,
     * and it will construct a canonicalized String representing a version of the URI that is safe to
     * run regex against.
	 * 
	 * NOTE:  This method will obey the ESAPI.properties configurations for allowing
	 * Mixed and Multiple Encoding URLs.  
     *
     * @param dirtyUri
     * @return Canonicalized URI string.
     * @throws IntrusionException
     */
    public String getCanonicalizedURI(URI dirtyUri) throws IntrusionException{

//        From RFC-3986 section 3
//          URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//
//                  hier-part   = "//" authority path-abempty
//                              / path-absolute
//                              / path-rootless
//                              / path-empty

//           The following are two example URIs and their component parts:
//
//                 foo://example.com:8042/over/there?name=ferret#nose
//                 \_/   \______________/\_________/ \_________/ \__/
//                  |           |            |            |        |
//               scheme     authority       path        query   fragment
//                  |   _____________________|__
//                 / \ /                        \
//                 urn:example:animal:ferret:nose
        Map<UriSegment, String> parseMap = new EnumMap<UriSegment, String>(UriSegment.class);
        parseMap.put(UriSegment.SCHEME, dirtyUri.getScheme());
        //authority   = [ userinfo "@" ] host [ ":" port ]
        parseMap.put(UriSegment.AUTHORITY, dirtyUri.getRawAuthority());
        parseMap.put(UriSegment.HOST, dirtyUri.getHost());
        //if port is undefined, it will return -1
        Integer port = new Integer(dirtyUri.getPort());
        parseMap.put(UriSegment.PORT, port == -1 ? "": port.toString());
        parseMap.put(UriSegment.PATH, dirtyUri.getRawPath());
        parseMap.put(UriSegment.QUERY, dirtyUri.getRawQuery());
        parseMap.put(UriSegment.FRAGMENT, dirtyUri.getRawFragment());

        //Replace all the items in the map with canonicalized versions.

        Set<UriSegment> set = parseMap.keySet();

        SecurityConfiguration sg = ESAPI.securityConfiguration();
        boolean allowMixed = sg.getBooleanProp("Encoder.AllowMixedEncoding");
        boolean allowMultiple = sg.getBooleanProp("Encoder.AllowMultipleEncoding");
        for(UriSegment seg: set){
        	String value = "";
            //In the case of a uri query, we need to break up and canonicalize the internal parts of the query.
            if(seg == UriSegment.QUERY && null != parseMap.get(seg)){
                StringBuilder qBuilder = new StringBuilder();
                try {
                    Map<String, List<String>> canonicalizedMap = this.splitQuery(dirtyUri);
                    Set<Entry<String, List<String>>> query = canonicalizedMap.entrySet();
                    Iterator<Entry<String, List<String>>> i = query.iterator();
                    while(i.hasNext()){
                        Entry<String, List<String>> e = i.next();
                        String key = e.getKey();
                        String qVal = "";
                        List<String> list = e.getValue();
                        if(!list.isEmpty()){
                            qVal = list.get(0);
                        }
                        qBuilder.append(key)
                        .append("=")
                        .append(qVal);

                        if(i.hasNext()){
                            qBuilder.append("&");
                        }
                    }
                    value = qBuilder.toString();
                } catch (UnsupportedEncodingException e) {
                    logger.debug(Logger.EVENT_FAILURE, "decoding error when parsing [" + dirtyUri.toString() + "]");
                }
            } else {
            	String extractedInput = parseMap.get(seg);
                value = canonicalize(extractedInput, allowMultiple, allowMixed);
                value = value == null ? "" : value;
            }
            //Check if the port is -1, if it is, omit it from the output.
            if(seg == UriSegment.PORT){
                if("-1" == parseMap.get(seg)){
                    value = "";
                }
            }
            parseMap.put(seg, value );
        }

        return buildUrl(parseMap);
    }

    /**
     * All the parts should be canonicalized by this point.  This is straightforward assembly.
     *
     * @param parseMap The parts of the URL to put back together.
     * @return The canonicalized URL.
     */
    protected String buildUrl(Map<UriSegment, String> parseMap){
        StringBuilder sb = new StringBuilder();
        boolean schemePresent = parseMap.get(UriSegment.SCHEME).equals("") ? false : true;
        
        if(schemePresent) {
        	sb.append(parseMap.get(UriSegment.SCHEME))
        	.append("://");
        }
        
        //can't use SCHEMESPECIFICPART for this, because we need to canonicalize all the parts of the query.
        //USERINFO is also deprecated.  So we technically have more than we need.
        sb.append(parseMap.get(UriSegment.AUTHORITY) == null || parseMap.get(UriSegment.AUTHORITY).equals("") ? "" : parseMap.get(UriSegment.AUTHORITY))
        .append(parseMap.get(UriSegment.PATH) == null || parseMap.get(UriSegment.PATH).equals("") ? ""  : parseMap.get(UriSegment.PATH))
        .append(parseMap.get(UriSegment.QUERY) == null || parseMap.get(UriSegment.QUERY).equals("")
                ? "" : "?" + parseMap.get(UriSegment.QUERY))
        .append((parseMap.get(UriSegment.FRAGMENT) == null) || parseMap.get(UriSegment.FRAGMENT).equals("")
                ? "": "#" + parseMap.get(UriSegment.FRAGMENT))
        ;
        return sb.toString();
    }

    public enum UriSegment {
        AUTHORITY, SCHEME, SCHEMSPECIFICPART, USERINFO, HOST, PORT, PATH, QUERY, FRAGMENT
    }


    /**
     * The meat of this method was taken from StackOverflow:  http://stackoverflow.com/a/13592567/557153
     * It has been modified to return a canonicalized key and value pairing.
     *
     * @param uri The URI to analyze.
     * @return a map of canonicalized query parameters.
     * @throws UnsupportedEncodingException
     */
    public Map<String, List<String>> splitQuery(URI uri) throws UnsupportedEncodingException {
      final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
      final String[] pairs = uri.getQuery().split("&");
      for (String pair : pairs) {
        final int idx = pair.indexOf("=");
        final String key = idx > 0 ? canonicalize(pair.substring(0, idx)) : pair;
        if (!query_pairs.containsKey(key)) {
          query_pairs.put(key, new LinkedList<String>());
        }
        final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
        query_pairs.get(key).add(canonicalize(value));
      }
      return query_pairs;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForJSON(String input) {
        if( input == null ) {
            return null;
        }
        return jsonCodec.encode(IMMUNE_JSON, input);
    }

    /**
     * {@inheritDoc}
     */
    public String decodeFromJSON(String input) {
        if( input == null ) {
            return null;
        }
        return jsonCodec.decode(input);
    }

}
