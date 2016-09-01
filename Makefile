CXX	= g++ -I/usr/local/include/Eigen -I/usr/local/include/cryptopp
CXXFLAGS= -O3 -std=c++11 -Wall
LDFLAGS = -lm

SOURCES = $(wildcard *.cpp)
HEADERS = $(wildcard *.h)
OBJECTS = $(SOURCES:.cpp=.o)
EXEC	= PKE
VERSION = 0.1
PACKAGE = $(EXEC)-$(VERSION)
MISC    = 

new: clean all
	
all: $(SOURCES) $(EXEC)

$(EXEC): $(OBJECTS) $(HEADERS) main.cpp
	$(CXX) -o $(EXEC) $(OBJECTS) $(LDFLAGS) $(IDFLAGS) $(CXXFLAGS)

.PHONY: clean distrib
clean:
	rm -f $(OBJECTS) $(EXEC)
	rm -rf $(PACKAGE) $(PACKAGE).tar.gz

$(PACKAGE).tar.gz: $(SOURCES) $(HEADERS) $(MISC) Makefile 
	mkdir $(PACKAGE)
	cp -f $(SOURCES) $(HEADERS) $(MISC) Makefile $(PACKAGE)
	tar czf $(PACKAGE).tar.gz $(PACKAGE)
	rm -rf $(PACKAGE)

distrib: clean $(PACKAGE).tar.gz
