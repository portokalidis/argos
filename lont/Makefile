
AXIS=/home/porto/projects/lont/axis-1_4/lib
CLASSPATH=$(AXIS)/axis-ant.jar:$(AXIS)/commons-logging-1.0.4.jar:$(AXIS)/axis.jar:$(AXIS)/jaxrpc.jar:$(AXIS)/saaj.jar:$(AXIS)/commons-discovery-0.2.jar:$(AXIS)/log4j-1.2.8.jar:$(AXIS)/wsdl4j-1.5.1.jar:.
#FLAGS=-Xlint
FLAGS=-classpath $(CLASSPATH)

.PHONY:all run clean

CLASSES=ArgosLontApp.class ArgosClient.class ClientProcessor.class CsiLog.class\
	ArgosSiggenApp.class CustomDataInput.class NetLog.class MemoryBlock.class\
	EthernetFrame.class Signature.class Unsigned.class StickyPoint.class\
	LontClient.class LontSigSubmit.class ResetTask.class

all: $(CLASSES)

%.class: %.java
	javac $(FLAGS) $<

siggen: ArgosSiggenApp.class

clean:
	rm -f *.class
	
