import java.io.*;

class EthernetFrame {
	private long base;
	private int size;
	private byte []data;

	public EthernetFrame(long base) {
		this.base = base;
	}

	public int readEthernetFrame(CustomDataInput in) throws EOFException, IOException {
		if (in.available() == 0) {
			return 0;
		}
		size = in.readUnsignedShort(false);
		data = new byte[size];
		in.readFully(data, 0, size);
		return size;
	}

	public boolean containsIndex(long idx) {
		if (base <= idx && (base + size) > idx) {
			return true;
		}
		return false;
	}

	public int size() {
		return size;
	}

	public byte []data() {
		return data;
	}

	public long base() {
		return base;
	}

	public void print() {
		System.out.println("Ethernet frame base: " + base + "\tSize: " + size);
	}

	public void printData() {
		int j;
		System.out.print("         ");
		for (j = 0; j < 25; j++) {
			System.out.printf("%2d ", j);
		}
		System.out.println();
		try {
			for (int i = 0; (i * 25) < size; i++) {
				System.out.printf("%7d: ", ((i * 25) + base));
				for (j = 0; j < 25; j++) {
					System.out.printf("%2X ", Unsigned.byteToUnsigned(data[(i * 25) + j]));
				}
				System.out.println();
			}
		} catch (ArrayIndexOutOfBoundsException e) {
		}
		System.out.println();
	}


}
