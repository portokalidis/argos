import java.io.*;
import java.util.Vector;
import java.util.Enumeration;
import java.math.BigInteger;


class CsiLog {
	// Csi log fields
	protected short format;
	protected short arch;
	protected int type;
	protected long ts;
	protected BigInteger []reg;
	protected BigInteger []rego;
	protected long []regn;
	protected BigInteger eip;
	protected BigInteger eipo;
	protected long eipn;
	protected BigInteger eflags;

	protected boolean netTrackerInfoExist;
	protected boolean bigEndianFormat;
	protected int unsignedLongBytes;
	protected int registersNumber;

	protected Vector<MemoryBlock> memoryBlocks;

	static final int NET_TRACKER_MASK = 128;
	static final int BIG_ENDIAN_MASK  = 64;
	static final int I386 = 0;
	static final int X86_64 = 1;


	static final int EAX = 0;
	static final int ECX = 1;
	static final int EDX = 2;
	static final int EBX = 3;
	static final int ESP = 4;
	static final int EBP = 5;
	static final int ESI = 6;
	static final int EDI = 7;

	static final int R8 = 8;
	static final int R9 = 9;
	static final int R10 = 10;
	static final int R11 = 11;
	static final int R12 = 12;
	static final int R13 = 13;
	static final int R14 = 14;
	static final int R15 = 15;

	static final String []REGNAME = { "EAX", "ECX", "EDX", "EBX", "ESP",
		"EBP", "ESI", "EDI", "R8", "R9", "R10", "R11", "R12", "R13",
		"R14", "R15" };

	static final int PADDR_LOOKUP = 0;
	static final int VADDR_LOOKUP = 1;
	

	public CsiLog() {
		netTrackerInfoExist = false;
		bigEndianFormat = false;
		unsignedLongBytes = 4;
		registersNumber = 8;
		memoryBlocks = new Vector<MemoryBlock>();
	}

	private void loadMemoryBlocks(CustomDataInput in) throws IOException, EOFException {
		MemoryBlock mb;

		while (true) {
			mb = new MemoryBlock();
			if (!mb.parseMemoryBlock(in, unsignedLongBytes, bigEndianFormat)) {
				break;
			}
			memoryBlocks.add(mb);
		}
	}

	private void loadRegisters(CustomDataInput in) throws IOException {
		int i, tmp;

		reg = new BigInteger[registersNumber];
		for (i = 0; i < registersNumber; i++) {
			reg[i] = in.readUnsignedBytes(unsignedLongBytes, false);
		}

		rego = new BigInteger[registersNumber];
		for (i = 0; i < registersNumber; i++) {
			rego[i] = in.readUnsignedBytes(unsignedLongBytes, false);
		}

		if (netTrackerInfoExist) {
			regn = new long[registersNumber];
			for (i = 0; i < registersNumber; i++) {
				regn[i] = in.readUnsignedInt(bigEndianFormat);
			}
		}

		eip = in.readUnsignedBytes(unsignedLongBytes, false);
		eipo = in.readUnsignedBytes(unsignedLongBytes, false);
		if (netTrackerInfoExist) {
			eipn = in.readUnsignedInt(bigEndianFormat);
		}
		eflags = in.readUnsignedBytes(unsignedLongBytes, false);
	}

	public void load(String logname) throws FileNotFoundException, IOException, EOFException {
		int i;
		File logfile = new File(logname);
		CustomDataInput in = new CustomDataInput(new DataInputStream(new BufferedInputStream(new FileInputStream(logfile))));

		// Read fields
		format = in.readUnsignedByte();
		if ((format & NET_TRACKER_MASK) != 0) {
			netTrackerInfoExist = true;
		}
		if ((format & BIG_ENDIAN_MASK) != 0) {
			bigEndianFormat = true;
			System.out.println("BigEndian: " + bigEndianFormat);
		}
		arch = in.readUnsignedByte();
		type = in.readUnsignedShort(bigEndianFormat);
		ts = in.readUnsignedInt(bigEndianFormat);
		if (arch == X86_64) {
			unsignedLongBytes = 8;
			registersNumber = 16;
		}
		loadRegisters(in);
		loadMemoryBlocks(in);
	}

	private void printHex(BigInteger i, int align) {
		String str = i.toString(16);
		System.out.print("0x");
		for (int j = str.length(); j < align; j++) {
			System.out.print("0");
		}
		System.out.print(str);
	}

	private void printLong(Long l, int align) {
		String str = l.toString();
		for (int j = str.length(); j < align; j++) {
			System.out.print(" ");
		}
		System.out.print(str);
	}

	public void print() {
		int b, i, j;
		String tmp;

		System.out.println("FORMAT\tARCH\tTYPE\tTS");
		System.out.println(format + "\t" + arch + "\t" + type + "\t" + ts);
		System.out.println();
		i = 0;
		if (arch == I386) {
			j = 4;
		} else {
			j = 3;
		}
		b = 0;
		do {
			for (i = b; i < (b + j); i++) {
				System.out.print(" " + REGNAME[i] + "\t\t");
			}
			System.out.println();
			for (i = b; i < (b + j); i++) {
				System.out.print(" ");
				printHex(reg[i], unsignedLongBytes * 2);
				System.out.print("\t");
			}
			System.out.println();
			for (i = b; i < (b + j); i++) {
				System.out.print("(");
				printHex(rego[i], unsignedLongBytes * 2);
				System.out.print(")\t");
			}
			System.out.println();
			if (netTrackerInfoExist) {
				for (i = b; i < (b + j); i++) {
					System.out.print("[");
					printLong(regn[i], unsignedLongBytes * 2 + 2);
					System.out.print("]\t");
				}
				System.out.println();
			}
			b = b + j;
		} while (i < registersNumber);

		System.out.println(" EIP\t\tEFLAGS");
		System.out.print(" ");
		printHex(eip, unsignedLongBytes * 2);
		System.out.print("\t");
		printHex(eflags, unsignedLongBytes * 2);
		System.out.println();
		System.out.print("(");
		printHex(eipo, unsignedLongBytes * 2);
		System.out.println(")\t");
		if (netTrackerInfoExist) {
			System.out.print("[");
			printLong(eipn, unsignedLongBytes * 2 + 2);
			System.out.println("]");
		}
	}

	public void printMemoryBlocks() {
		MemoryBlock mb;
		int n;

		System.out.println("Block#\tFormat\tTainted\tSize\tVADDR\t\tPADDR");
		n = 0;
		for (Enumeration e = memoryBlocks.elements(); e.hasMoreElements(); ) {
			mb = (MemoryBlock)e.nextElement();
			System.out.print(n + "\t" + mb.format() + "\t" + mb.isTainted() + "\t" + mb.size() + "\t");
			printHex(mb.vaddr(), unsignedLongBytes * 2);
			System.out.print("\t");
			printHex(mb.paddr(), unsignedLongBytes * 2);
			System.out.println();
			n = n + 1;
		}
	}

	public BigInteger getRegisterValue(int reg) {
		return this.reg[reg];
	}

	public BigInteger getRegisterOrigin(int reg) {
		return this.rego[reg];
	}
	
	public long getRegisterNetidx(int reg) {
		if (netTrackerInfoExist) {
			return this.regn[reg];
		}
		return 0;
	}

	public BigInteger getEIPOrigin() {
		return this.eipo;
	}

	public BigInteger getEIPValue() {
		return this.eip;
	}

	public long getEIPNetidx() {
		return this.eipn;
	}

	public int getUlongSize() {
		if (arch == I386) {
			return 4;
		}
		return 8;
	}

	public MemoryBlock findMemoryBlock(BigInteger addr, int mode) {
		MemoryBlock mb;
		if (mode == PADDR_LOOKUP) {
			for (Enumeration e = memoryBlocks.elements(); e.hasMoreElements(); ) {
				mb = (MemoryBlock)e.nextElement();
				if (mb.containsPaddr(addr)) {
					return mb;
				}
			}
		} else if (mode == VADDR_LOOKUP) {
			for (Enumeration e = memoryBlocks.elements(); e.hasMoreElements(); ) {
				mb = (MemoryBlock)e.nextElement();
				if (mb.containsVaddr(addr)) {
					return mb;
				}
			}
		}
		return null;
	}

	public MemoryBlock getPreviousMemoryBlock(MemoryBlock mb) {
		MemoryBlock previous;
		int i;
		i = memoryBlocks.indexOf(mb);
		if (i == 0) return null;
		return memoryBlocks.get(i - 1);
	}

	public MemoryBlock getNextMemoryBlock(MemoryBlock mb) {
		MemoryBlock next;
		int i;
		i = memoryBlocks.indexOf(mb);
		if (++i == memoryBlocks.size()) return null;
		return memoryBlocks.get(i);
	}
}
