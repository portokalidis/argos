import java.io.*;
import java.math.BigInteger;

class CustomDataInput {
	DataInputStream in;

	public CustomDataInput(DataInputStream in) {
		this.in = in;
	}

	public static void swapByteArray(byte []ulong) {
		int i;
		byte b;
		for (i = 0; i < (ulong.length / 2); i++) {
			 b = ulong[ulong.length - i - 1];
			 ulong[ulong.length - i - 1] = ulong[i];
			 ulong[i] = b;
		}
	}

	public boolean readBoolean() throws IOException {
		return in.readBoolean();
	}

	public short readUnsignedByte() throws IOException {
		return (short)in.readUnsignedByte();
	}

	public BigInteger readUnsignedBytes(int n, boolean bigEndian) throws IOException, EOFException {
		byte []b;
		BigInteger bigInt;
		int s;

		b = new byte[n];
		in.readFully(b, 0, n);
		if (!bigEndian) {
			swapByteArray(b);
		}
		return new BigInteger(1, b);
	}

	public BigInteger readUnsignedLong(boolean bigEndian) throws IOException, EOFException {
		return readUnsignedBytes(8, bigEndian);
	}

	public long readUnsignedInt(boolean bigEndian) throws IOException, EOFException {
		return readUnsignedBytes(4, bigEndian).longValue();
	}

	public int readUnsignedShort(boolean bigEndian) throws IOException, EOFException {
		return readUnsignedBytes(2, bigEndian).intValue();
	}

	public void readFully(byte []b, int off, int len) throws IOException, EOFException {
		in.readFully(b, off, len);
	}

	public int available() throws IOException {
		return in.available();
	}
}
