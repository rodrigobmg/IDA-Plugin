include ../allmake.mak

GOALS += bats
.PHONY: $(GOALS)
all: $(GOALS)

#######################################################################
# .bat files

ifdef __NT__
  BATS += $(RS)cl32.bat
  BATS += $(RS)m.bat
  BATS += $(RS)m32.bat
  BATS += $(RS)mso.bat
  BATS += $(RS)mso32.bat
endif
bats: $(BATS)

UMLIB=$(call shortdospath, $(WSDKPATH)/lib/$(WSDKVER)/um/$1)
# the following functions accept the path to main VS dirs $(VSPATH) and $(MSSDK).
VCLIB=$(1)/lib/$(3);$(UCRT_LIB)/$(3);$(2)/lib/$(3);$(call UMLIB,$(3))
VCOLD32LIB=$(1)/lib/x86;$(UCRT_LIB)/x86;$(2)/lib

VCINC=$(1)/Include;$(UCRT_INCLUDE);$(2)/include/um;$(2)/include/shared
VC32BIN=$(1)/bin/HostX86/x86;$(2)/bin;$(QTDIR)bin
$(RS)cl32.bat: makefile ../allmake.mak ../defaults.mk
	@echo "@echo off" >$@
	@echo "setlocal" >>$@
	@echo "set VSPATH=$(VSPATH)" >>$@
	@echo "set MSSDK=$(MSSDK)" >>$@
	@echo "set LIB=$(call VCLIB,%VSPATH%,%MSSDK%,x86)" >>$@
	@echo "set INCLUDE=$(call VCINC,%VSPATH%,%MSSDK%)" >>$@
	@echo "set PATH=$(call VC32BIN,%VSPATH%,%MSSDK%)" >>$@
	@echo "cl.exe %*" >>$@
	@chmod +x $@

$(RS)m32.bat: makefile ../allmake.mak ../defaults.mk
	@echo "@echo off" >$@
	@echo "setlocal" >>$@
	@echo "set VSPATH=$(VSPATH)" >>$@
	@echo "set MSSDK=$(MSSDK)" >>$@
	@echo "set LIB=$(call VCLIB,%VSPATH%,%MSSDK%,x86)" >>$@
	@echo "set PATH=%MSSDK%bin;%PATH%" >>$@
	@echo "set __NT__=1" >>$@
	@echo "set __X86__=1" >>$@
	@echo "make %*" >>$@
	@chmod +x $@

$(RS)m.bat: makefile ../allmake.mak ../defaults.mk
	@echo "@echo off" >$@
	@echo "setlocal" >>$@
	@echo "set VSPATH=$(VSPATH)" >>$@
	@echo "set MSSDK=$(MSSDK)" >>$@
	@echo "set LIB=$(call VCLIB,%VSPATH%,%MSSDK%,x64)" >>$@
	@echo "set PATH=%MSSDK%bin;%PATH%" >>$@
	@echo "set __NT__=1" >>$@
	@echo "set NDEBUG=1" >>$@
	@echo "make %*" >>$@
	@chmod +x $@

$(RS)mso32.bat: makefile ../allmake.mak ../defaults.mk
	@echo "@echo off" >$@
	@echo "setlocal" >>$@
	@echo "set VSPATH=$(VSPATH)" >>$@
	@echo "set MSSDK=$(MSSDK71)" >>$@
	@echo "set LIB=$(call VCOLD32LIB,%VSPATH%,%MSSDK%)" >>$@
	@echo "set PATH=%MSSDK%bin;%PATH%" >>$@
	@echo "set __NT__=1" >>$@
	@echo "set __XPCOMPAT__=1" >>$@
	@echo "set NDEBUG=1" >>$@
	@echo "set USE_STATIC_RUNTIME=1" >>$@
	@echo "set __X86__=1" >>$@
	@echo "make %*" >>$@
	@chmod +x $@

$(RS)mso.bat: makefile ../allmake.mak ../defaults.mk
	@echo "@echo off" >$@
	@echo "setlocal" >>$@
	@echo "set VSPATH=$(VSPATH)" >>$@
	@echo "set MSSDK=$(MSSDK71)" >>$@
	@echo "set LIB=$(call VCLIB,%VSPATH%,%MSSDK%,x64)" >>$@
	@echo "set PATH=%MSSDK%bin;%PATH%" >>$@
	@echo "set __NT__=1" >>$@
	@echo "set __XPCOMPAT__=1" >>$@
	@echo "set NDEBUG=1" >>$@
	@echo "set USE_STATIC_RUNTIME=1" >>$@
	@echo "make %*" >>$@
	@chmod +x $@
