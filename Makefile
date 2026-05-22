TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShopeeTaskHook

ShopeeTaskHook_FILES = Tweak.xm
ShopeeTaskHook_FRAMEWORKS = Foundation UIKit
ShopeeTaskHook_CFLAGS = -fobjc-arc -Wno-error=deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk

