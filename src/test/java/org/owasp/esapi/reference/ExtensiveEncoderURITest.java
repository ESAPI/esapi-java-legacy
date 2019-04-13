package org.owasp.esapi.reference;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
	static List<String> inputs = new ArrayList<String>();
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
		String fileName = url.getFile();
		File urisForText = new File(fileName);
		
		inputs = Files.readAllLines(urisForText.toPath(), StandardCharsets.UTF_8);
		
		return inputs;
	}
	
	@Test
	public void testUrlsFromFile() throws Exception{
		assertEquals(this.expected, v.isValidURI("URL", uri, false));
	}

}
