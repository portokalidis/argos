import java.io.*;
import java.math.BigInteger;

class MemoryBlock {
	private int format;
	private boolean tainted;
	private int size;
	private BigInteger paddr;
	private BigInteger vaddr;
	private byte []memdata;
	private long []netidx;

	public boolean parseMemoryBlock(CustomDataInput in, int unsignedLongBytes, boolean bigEndianFormat) throws IOException, EOFException {
		format = in.readUnsignedByte();
		if (format == 0) {
			return false;
		}
		if (in.readUnsignedByte() == 0) {
			tainted = false;
		} else {
			tainted = true;
		}
		size = in.readUnsignedShort(bigEndianFormat);
		paddr = in.readUnsignedBytes(unsignedLongBytes, false);
		vaddr = in.readUnsignedBytes(unsignedLongBytes, false);
		memdata = new byte[size];
		in.readFully(memdata, 0, size);
		if ((format & CsiLog.NET_TRACKER_MASK) != 0) {
			netidx = new long[size];
			for (int j = 0; j < size; j++) {
				netidx[j] = in.readUnsignedInt(bigEndianFormat);
			}
		}
		return true;
	}

	public BigInteger paddr() {
		return paddr;
	}
	
	public BigInteger vaddr() {
		return vaddr;
	}
	
	public int size() {
		return size;
	}

	public int format() {
		return format;
	}

	public boolean isTainted() {
		return tainted;
	}

	public boolean hasNetInfo() {
		if ((format & CsiLog.NET_TRACKER_MASK) != 0) {
			return true;
		}
		return false;
	}

	public byte [] data() {
		return memdata;
	}

	public void copyData(byte []buf, int off) {
		for (int i = 0; i < size; i++) {
			buf[i + off] = memdata[i];
		}
	}

	public long [] netData() {
		if (hasNetInfo()) {
			return netidx;
		}
		return null;
	}

	public boolean containsPaddr(BigInteger addr) {
		if (paddr.compareTo(addr) <= 0 && 
				paddr.add(BigInteger.valueOf(size)).compareTo(addr) > 0) {
			return true;
		}
		return false;
	}

	public boolean containsVaddr(BigInteger addr) {
		if (vaddr.compareTo(addr) <= 0 && 
				vaddr.add(BigInteger.valueOf(size)).compareTo(addr) > 0) {
			return true;
		}
		return false;
	}

	public void print() {
		System.out.println("VADDR: 0x" + vaddr.toString(16) + "\tPADDR: 0x" + paddr.toString(16) + "\tSize: " + size + "\tTainted: " + tainted);
	}

	public void printData() {
		int j;
		int base = vaddr.intValue() & 0xFFF;
		int split = 16;

		if (hasNetInfo()) {
			split = 8;
		}

		System.out.print("      ");
		for (j = 0; j < split; j++) {
			System.out.printf("%7d ", j);
		}
		System.out.println();
		try {
			for (int i = 0; (i * split) < size; i++) {
				System.out.printf("%3x: ", ((i * split) + base));
				for (j = 0; j < split; j++) {
					if (hasNetInfo()) {
						System.out.printf("[%2X:%4d] ", Unsigned.byteToUnsigned(memdata[(i * split) + j]), netidx[(i * split) +j]);
					} else {
						System.out.printf("%2X ", Unsigned.byteToUnsigned(memdata[(i * split) + j]));
					}
				}
				System.out.println();
			}
		} catch (ArrayIndexOutOfBoundsException e) {
		}
		System.out.println();
	}
}

