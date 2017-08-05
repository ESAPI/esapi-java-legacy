package org.owasp.esapi.codecs;

public abstract class AbstractCharacterCodec extends AbstractCodec<Character> {
	/* (non-Javadoc)
	 * @see org.owasp.esapi.codecs.Codec#decode(java.lang.String)
	 */
	@Override
	public String decode(String input) {
		StringBuilder sb = new StringBuilder();
		PushbackSequence<Character> pbs = new PushbackString(input);
		while (pbs.hasNext()) {
			Character c = decodeCharacter(pbs);
			if (c != null) {
				sb.append(c);
			} else {
				sb.append(pbs.next());
			}
		}
		return sb.toString();
	}
}
