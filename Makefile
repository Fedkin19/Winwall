ifeq ($(OS),Windows_NT)
    HOST_OS := Windows
    EXE_EXT := .exe
    RM      := del /Q
    NULL    := 2>NUL
else
    HOST_OS := Unix
    EXE_EXT :=
    RM      := rm -f
    NULL    := 2>/dev/null
endif

TARGET  := firewall-cli$(EXE_EXT)
SRCS    := main.cpp
OBJS    := $(SRCS:.cpp=.o)
DEPS    := $(SRCS:.cpp=.d)
HDRS    := firewall.hpp

ifeq ($(MSVC),1)

CXX      := cl
CXXFLAGS := /nologo /EHsc /std:c++17 /O2 /W4 /MD /DUNICODE /D_UNICODE
LDFLAGS  := /nologo
LDLIBS   := ole32.lib oleaut32.lib netfw.lib shell32.lib uuid.lib

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) /Fe$@ $(OBJS) $(LDLIBS)

main.obj: main.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) /c main.cpp /Fo$@

clean:
	-@$(RM) *.obj *.exe *.pdb *.ilk *.exp *.lib $(NULL) || exit 0

else

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic \
            -municode -DUNICODE -D_UNICODE -MMD -MP
LDFLAGS  ?= -municode -static -static-libgcc -static-libstdc++
LDLIBS   := -lole32 -loleaut32 -lnetfw -lshell32 -luuid

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	-@$(RM) $(OBJS) $(DEPS) $(TARGET) $(NULL) || exit 0

endif

.PHONY: all run clean help

all: $(TARGET)

run: $(TARGET)
	./$(TARGET) help

help:
	@echo "  all    - build $(TARGET)"
	@echo "  run    - run help"
	@echo "  clean  - remove artifacts"
	@echo "  help   - this help"