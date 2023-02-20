class Unsigned {
	public static int byteToUnsigned(byte b) {
		int u;
		u = b & 0x7F;
		if (b < 0) {
			u += 0x80;
		}
		return u;
	}
}
