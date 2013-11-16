/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
 * Copyright (c) 2011, Mike Samuel [Convert from XML to Java]
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.  Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials
 * provided with the distribution.  Neither the name of OWASP nor the names
 * of its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.esapi.reference.validation;

import org.owasp.html.AttributePolicy;
import org.owasp.html.Handler;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamRenderer;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.IntrusionException;

import java.io.IOException;

/**
 * This class implements the
 * {@link AntiSamy https://www.owasp.org/index.php/Antisamy} functionality
 * and its basic policy file originally used with ESAPI 2.0.1. It is intended
 * to be immune to XSS and CSS phishing attacks.
 *
 * This code based on AntiSamyTest.java at:
 * http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/src/tests/org/owasp/html/AntiSamyTest.java
 * by Mike Samuel. It has been rewritten (mostly be stripping out the JUnit
 * tests) to be used with ESAPI.
 *
 * @author Arshan Dabirsiaghi (original AntiSamy rules, expressed as XML)
 * @author Mike Samuel (converted AntiSamy XML rules to Java for HTML Sanitizer)
 */
public class HTMLSanitizerAntiSamyPolicy {
  private static final Logger logger = ESAPI.getLogger("HTMLSanitizerAntiSamyRules");
  private static HtmlSanitizer.Policy makePolicy(Appendable buffer) {
    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        buffer,
        new Handler<IOException>() {
          public void handle(IOException ex) {
		  // OPEN ITEM: Some other exception type more appropriate here?
            throw new IntrusionException("Error creating AntiSamy policy for HTML Sanitizer", ex);
          }
        },
        new Handler<String>() {
          public void handle(String errorMessage) {
            logger.error(Logger.SECURITY_FAILURE, errorMessage);
	    // OPEN ITEM: Should we also throw something here??? If so what?
          }
        });

    return new HtmlPolicyBuilder()
        .allowElements(
            "a", "b", "br", "div", "font", "i", "img", "input", "li",
            "ol", "p", "span", "td", "ul")
        .allowAttributes("checked", "type").onElements("input")
        .allowAttributes("color").onElements("font")
        .allowAttributes("href").onElements("a")
        .allowAttributes("src").onElements("img")
        .allowAttributes("class", "id", "title").globally()
        .allowAttributes("char").matching(
            new AttributePolicy() {
              public String apply(
                  String elementName, String attributeName, String value) {
                return value.length() == 1 ? value : null;
              }
            }).onElements("td")
        .allowStandardUrlProtocols()
        .requireRelNofollowOnLinks()
        .allowStyling()
        .build(renderer);
  }

  public static String sanitize(String dirtyHtml) {
    StringBuilder sb = new StringBuilder();

    HtmlSanitizer.sanitize(dirtyHtml, makePolicy(sb));

    return sb.toString();
  }
}