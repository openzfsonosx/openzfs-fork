sbin_PROGRAMS   += InvariantDisks
CPPCHECKTARGETS += InvariantDisks

AM_LIBTOOLFLAGS += --tag=CXX

InvariantDisks_SOURCES = \
	IDLogUtils.cpp \
	IDLogUtils.hpp \
	IDBaseLinker.cpp \
	IDBaseLinker.hpp \
	IDCLI.cpp \
	IDCLI.hpp \
	IDDAHandlerIdle.cpp \
	IDDAHandlerIdle.hpp \
	IDDiskArbitrationDispatcher.cpp \
	IDDiskArbitrationDispatcher.hpp \
	IDDiskArbitrationHandler.hpp \
	IDDiskArbitrationUtils.cpp \
	IDDiskArbitrationUtils.hpp \
	IDDiskInfoLogger.cpp \
	IDDiskInfoLogger.hpp \
	IDDispatchUtils.cpp \
	IDDispatchUtils.hpp \
	IDException.cpp \
	IDException.hpp \
	IDFileUtils.mm \
	IDFileUtils.hpp \
	IDImagePathLinker.cpp \
	IDImagePathLinker.hpp \
	IDMediaPathLinker.cpp \
	IDMediaPathLinker.hpp \
	IDSerialLinker.cpp \
	IDSerialLinker.hpp \
	IDSymlinkHandle.cpp \
	IDSymlinkHandle.hpp \
	IDUUIDLinker.cpp \
	IDUUIDLinker.hpp \
	git-version.h \
	main.cpp

InvariantDisks_CXXFLAGS = -std=c++11 -stdlib=libc++
InvariantDisks_OBJCXXFLAGS = -std=c++11 -stdlib=libc++
InvariantDisks_LDFLAGS = -static -framework IOKit -framework DiskArbitration -framework CoreFoundation -framework Foundation
