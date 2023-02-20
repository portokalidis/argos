import java.math.BigInteger;
import java.util.Vector;
import java.util.Enumeration;
import java.io.*;

class Signature {
	protected CsiLog csiLog;
	protected NetLog netLog;
	protected String signature;
	protected int signatureLength;
	protected static final int vicinity = 16;
	protected static final int netVicinity = 64;

	public static int minimumSignatureLength = 20;

	public Signature(CsiLog c, NetLog n) {
		csiLog = c;
		netLog = n;
		signature = null;
		signatureLength = 0;
	}

	protected static boolean printByte(PrintStream printer, byte b, boolean escaping) {
		int i;

		if (b >= 33 && b <= 126 && b != 124) {
			if (escaping) {
				printer.print('|');
				escaping = false;
			}
			printer.printf("%c", b);
		} else {
			if (!escaping) {
				printer.print('|');
				escaping = true;
			} else 
				printer.print(' ');
			i = Unsigned.byteToUnsigned(b);
			if (i < 16)
				printer.print('0');
			printer.printf("%X", i);
		}
		return escaping;
	}


	protected boolean stickyPointsToSignature(Vector<StickyPoint> points) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrintStream printer = new PrintStream(out);
		byte []b;
		boolean escaping = false;

		signatureLength = 0;
		for (Enumeration e = points.elements(); e.hasMoreElements(); ) {
			b = ((StickyPoint)e.nextElement()).getStickyBytes();
			for (int i = 0; i < b.length; i++)
				escaping = printByte(printer, b[i], escaping);
			signatureLength += b.length;
		}
		if (escaping) printer.print('|');
		try {
			signature = out.toString("ASCII");
		} catch (UnsupportedEncodingException e) {
			System.err.println(e);
			return false;
		}
		return true;
	}

	protected boolean bytesToSignature(byte []buf, int off, int len) {
		boolean escaping = false;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrintStream printer = new PrintStream(out);

		for (int i = 0; i < len; i++) {
			escaping = printByte(printer, buf[off + i], escaping);
		}
		signatureLength = len;
		if (escaping) printer.print('|');
		try {
			signature = out.toString("ASCII");
		} catch (UnsupportedEncodingException e) {
			System.err.println(e);
			return false;
		}
		return true;
	}


	protected boolean generate(MemoryBlock m, int midx, EthernetFrame e,  int nidx) {
		byte [] memdata, netdata;
		int i, ulongSize, pnoff, stickyPointsLength;
		long pnidx, distance;
		StickyPoint p;
		Vector<StickyPoint> stickyPoints;
		MemoryBlock prevPage;

		ulongSize = csiLog.getUlongSize();
		memdata = m.data();
		netdata = e.data();
		//System.out.println("nidx="+nidx+" midx="+midx);

		p = StickyPoint.findStickyPoint(netdata, nidx, memdata, midx, ulongSize, vicinity);
		if (p == null) return false; // No sticky point found
		//System.out.println("Memory and net data stick: "+p.toString());


		p.growLeft();
		p.growRight();
		//System.out.println("After growing sticky point: "+p.toString());
		stickyPoints = new Vector<StickyPoint>();
		stickyPoints.add(p);
		stickyPointsLength = p.size();

		// Look for adjacent memory pages
		/* NO PATTERNS
		prevPage = m;
		while (p.slidePoint() > 0 && p.stickyPoint() == 0) {
			// Get Previous page
			prevPage = csiLog.getPreviousMemoryBlock(prevPage);
			if (prevPage == null) break;
			if (!prevPage.isTainted() || !prevPage.hasNetInfo())
				continue;
			pnidx = prevPage.netData()[prevPage.size() - 1];
			pnoff = (int)(pnidx - e.base());
			if (pnoff < 0) break;
			distance = Math.abs(e.base() + p.slidePoint() - pnidx);
			if (distance > netVicinity)
				break;
			p = StickyPoint.findStickyPoint(netdata, pnoff, prevPage.data(), prevPage.size() - 1, 4, vicinity);
			if (p == null) break;
			p.growLeft();
			p.growRight();
			//if (p.size() < minimumSignatureLength)
				//break;
			stickyPoints.add(p);
			stickyPointsLength += p.size();
		}
		*/

		// Generate signature b
		if (stickyPointsLength < minimumSignatureLength) {
			//System.out.println("Signature will be solely based on network trace");
			// Rough estimation
			// ethernet header 14 bytes
			// ip header 20 bytes
			// tcp header 20 bytes
			// tcp timstamps 12 bytes
			int offset = 14 + 20 + 20 + 12;
			// ethernet crc 4 bytes
			int trailer = 4;
			if ((netdata.length - offset - trailer) < minimumSignatureLength) {
				//System.out.println("Not enough network bytes to create signature");
				return false;
			}
			return bytesToSignature(netdata, offset, netdata.length - offset - trailer);
		}
		return stickyPointsToSignature(stickyPoints);
	}

	public boolean generate() {
		BigInteger target;
		MemoryBlock mb;
		EthernetFrame ef;
		long []netdata;
		long nidx, distance;
		int midx;

		byte []memBuffer;

		target = csiLog.getEIPOrigin();
		if (target.compareTo(BigInteger.ZERO) == 0) {
			//System.out.println("Exploit source does not exist");
			//System.out.println("Using exloit target instead");
			target = csiLog.getEIPValue();
			mb = csiLog.findMemoryBlock(target, CsiLog.VADDR_LOOKUP);
			if (mb == null) {
				System.err.println("Memory block not found");
				return false;
			}
			if (!mb.isTainted()) {
				System.err.println("Memory block is not tainted");
				return false;
			}
			if (!mb.hasNetInfo()) {
				System.err.println("Memory block does not contain net tracker info");
				return false;
			}
			midx = target.subtract(mb.vaddr()).intValue();
			netdata = mb.netData();
			nidx = netdata[midx];
		} else {
			//System.out.println("Exploit source exists");
			mb = csiLog.findMemoryBlock(target, CsiLog.PADDR_LOOKUP);
			if (mb == null) {
				System.err.println("Memory block not found");
				return false;
			}
			midx = target.subtract(mb.paddr()).intValue();
			nidx = csiLog.getEIPNetidx();
		}
		ef = netLog.findEthernetFrame(nidx);
		if (ef == null) {
			System.err.println("Ethernet frame not found ("+ nidx +")");
			return false;
		}
		/*
		System.out.println("Using memory block: ");
		mb.print();
		mb.printData();
		System.out.print("Using ethernet frame: ");
		ef.print();
		ef.printData();
		*/
		//System.out.println("Generating signature...");
		return generate(mb, midx, ef, (int)(nidx - ef.base()));
	}

	public String getString() {
		return signature.toString();
	}

	public int getLength() {
		return signatureLength;
	}
}
