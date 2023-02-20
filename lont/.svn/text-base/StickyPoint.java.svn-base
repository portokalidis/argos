class StickyPoint {
	protected byte [] slideBuf, stickyBuf;
	protected int off1, off2, relOff;
	protected int len;

	public StickyPoint(byte []b1, int o1, byte []b2, int o2, int r, int len) {
		slideBuf = b1;
		off1 = o1;
		stickyBuf = b2;
		off2 = o2;
		relOff = r;
		this.len = len;
	}

	public int slidePoint() {
		return off1 + relOff;
	}

	public int stickyPoint() {
		return off2;
	}

	public int size() {
		return len;
	}

	public boolean growLeft() {
		int i = 1;
		try {
			while (slideBuf[off1 + relOff - i] == stickyBuf[off2 - i]) {
				++i;
			}
		} catch (ArrayIndexOutOfBoundsException e) {
		} finally {
			--i;
		}

		if (i > 0) {
			off1 -= i;
			off2 -= i;
			len += i;
			return true;
		}
		return false;
	}

	public boolean growRight() {
		int i = 1;
		try { 
			while (slideBuf[off1 + relOff + len + i] == stickyBuf[off2 + len + i]) {
				++i;
			}
		} catch (ArrayIndexOutOfBoundsException e) {
		} finally {
			--i;
		}

		if (i > 0) {
			len += i;
			return true;
		}
		return false;
	}

	public String toString() {
		if (relOff < 0) return new String("[("+len+") << "+(-relOff)+"]");
		else if (relOff > 0) return new String("[("+len+") >> "+relOff+"]");
		return new String("[("+len+")]");
	}

	public byte[] getStickyBytes() {
		byte [] buf = new byte[len];
		for (int i = 0; i < len; i++)
			buf[i] = stickyBuf[off2 + i];
		return buf;
	}

	public static StickyPoint findStickyPoint(byte []b1, int o1, byte []b2, int o2, int len, int fuzzy) {
		int longestMatch = 0, longestMatchIdx = 0;
		int j, slide, slideMax;

		// Adjust slide so we don't get out of bounds
		slideMax = fuzzy;
		if (slideMax > o1)
			slideMax = o1;
		if (slideMax > o2)
			slideMax = o2;
		// look back
		for (slide = j = 0; slide < slideMax; ) {
			if (b1[o1 - slide + j] == b2[o2 + j]) {
				if (++j > longestMatch) {
					longestMatch = j;
					longestMatchIdx = - slide;
					if (j == len)
						break;
				}
				continue;
			} 
			j = 0;
			++slide;
		}

		if (j == len)
			return new StickyPoint(b1, o1, b2, o2, longestMatchIdx, len);

		// Re-adjust slide so we don't get out of bounds
		slideMax = fuzzy;
		if (slideMax > (b1.length - o1))
			slideMax = (b1.length - o1);
		if (slideMax > (b2.length - o2))
			slideMax = (b2.length - o2);
		// look forward
		for (slide = 1, j = 0; slide < slideMax; ) {
			if (b1[o1 + slide + j] == b2[o2 + j]) {
				if (++j > longestMatch) {
					longestMatch = j;
					longestMatchIdx = slide;
					if (j == len)
						break;
				}
				continue;
			}
			j = 0;
			++slide;
		}

		if (longestMatch == 0) return null;
		return new StickyPoint(b1, o1, b2, o2, longestMatchIdx, longestMatch);
	}

}
