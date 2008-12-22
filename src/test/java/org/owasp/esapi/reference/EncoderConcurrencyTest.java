package org.owasp.esapi.reference;

import org.owasp.esapi.ESAPI;

/**
 *
 * @author jwilliams
 */
public class EncoderConcurrencyTest implements Runnable {

    /**
     *
     */
    public int num = 0;
	
    /**
     *
     * @param args
     */
    public static void main(String[] args) {
		EncoderConcurrencyTest[] threads = new EncoderConcurrencyTest[10];
		for (int i = 0; i < 2; i++) {
			threads[i] = new EncoderConcurrencyTest();
			threads[i].num = i;
			new Thread( threads[i] ).start();
		}
	}

    /**
     *
     */
    public void run() {
		while( true ) {
			String nonce = ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS );
			String result = javaScriptEncode( nonce );
			System.out.println( Thread.currentThread().getName() + "\t" + result);
		}
	}

    /**
     *
     * @param str
     * @return
     */
    public static String control( String str ) {
		StringBuffer sb = new StringBuffer( str );
		return sb.reverse().toString();
	}
	
    /**
     *
     * @param str
     * @return
     */
    public static String javaScriptEncode(String str) {
		DefaultEncoder encoder = new DefaultEncoder();
		return encoder.encodeForJavaScript(str);
	}

}
