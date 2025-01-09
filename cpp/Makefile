OPENSSLV=/opt/openssl/openssl-1.1.1t
CPR=/usr/local
JSON=/opt/json/include

# If building locally, you need to install cpr (rest API) and nlohmann/json 
# then set these for your host machine:
# CPR=/usr/local
# OPENSSLV=/usr/local/opt/openssl@1.1

CXX				= g++ -std=c++17
RM				= rm -f
INCLUDES        = -I . \
				-I $(OPENSSLV)/include  \
				-I $(CPR)/include \
				-I $(JSON)
CXXFLAGS        = -g -Wall ${INCLUDES}
OBJS            = main.o utils.o tsInterface.o x509_generator.o
PROG            = x509_generator
LIBS            = -L $(OPENSSLV)/lib -L $(CPR)/lib -lcrypto -lssl -lcpr

all:            $(PROG)

debug: 			CXXFLAGS+= -DDEBUG -g -Wall ${INCLUDES}
debug: 			$(PROG)

${PROG}:		$(OBJS)
				$(CXX) $(INCLUDES) -o $(PROG) $(OBJS) $(LIBS)

clean:;         $(RM) -f $(PROG) core *.o
