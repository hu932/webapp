TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Ajie

Ajie_FILES = Tweak.xm
Ajie_FRAMEWORKS = Foundation UIKit
Ajie_LIBRARIES = z
Ajie_CFLAGS = -fobjc-arc -Wno-error=deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk
