package org.owasp.esapi.reference;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Validator;


@RunWith(Parameterized.class)
public class ExtensiveEncoderURITest {
	static List<String> inputs = new ArrayList<>();
	Validator v = ESAPI.validator();
	String uri;
	boolean expected;
	
	public ExtensiveEncoderURITest(String uri){
		String[] values = uri.split(","); 
		this.uri = values[0];
		this.expected = Boolean.parseBoolean(values[1]);
	}
	
	@Parameters
	public static Collection<String> getMyUris() throws Exception{
		URL url = ExtensiveEncoderURITest.class.getResource("/urisForTest.txt");

		try( BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8)) ) {
			inputs = readAllLines(br);
		}
		return inputs;
	}

	private static List<String> readAllLines(BufferedReader br) throws IOException {
		List<String> lines = new ArrayList<>();
		String line;
		while ((line = br.readLine()) != null) {
			lines.add(line);
		}
		return lines;
	}

	@Test
	public void testUrlsFromFile() {
		assertEquals(this.expected, v.isValidURI("URL", uri, false));
	}

}
