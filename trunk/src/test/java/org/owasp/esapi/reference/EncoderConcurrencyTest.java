package org.owasp.esapi.reference;

import org.owasp.esapi.ESAPI;

public class EncoderConcurrencyTest implements Runnable {

	public int num = 0;
	
	public static void main(String[] args) {
		EncoderConcurrencyTest[] threads = new EncoderConcurrencyTest[10];
		for (int i = 0; i < 2; i++) {
			threads[i] = new EncoderConcurrencyTest();
			threads[i].num = i;
			new Thread( threads[i] ).start();
		}
	}

	@Override
	public void run() {
		while( true ) {
			String nonce = ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS );
			String result = javaScriptEncode( nonce );
			System.out.println( Thread.currentThread().getName() + "\t" + result);
		}
	}

	public static String control( String str ) {
		StringBuffer sb = new StringBuffer( str );
		return sb.reverse().toString();
	}
	
	public static String javaScriptEncode(String str) {
		DefaultEncoder encoder = new DefaultEncoder();
		return encoder.encodeForJavaScript(str);
	}

}
