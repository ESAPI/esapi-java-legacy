package org.owasp.esapi.util;

// The "perfect" helper class for testing JUnit test, ObjFactoryTest.
// For testing only. Doesn't work as an inner class in ObjFactoryTest.
// Props to D. Adams for HG2G. RIP.
public class ThePrefectClass {
	private static final int lifeUniverseEverything = 42;
	public ThePrefectClass() {
		throw new UnsupportedOperationException("This public CTOR is not supported!");
	}
	public int getAnswer() { return lifeUniverseEverything; }
}
