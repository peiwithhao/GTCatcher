TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e

THEOS_PACKAGE_SCHEME = rootless

export THEOS_DEVICE_IP=localhost
export THEOS_DEVICE_PORT=2345
export THEOS_DEVICE_PASSWORD="123.com"

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GTCatcher

GTCatcher_FILES = Tweak.xm fishhook.c GTExtraContext.m
GTCatcher_CFLAGS = -fobjc-arc
GTCatcher_FRAMEWORKS = Foundation Security Network
GTCatcher_PRIVATE_FRAMEWORKS =

include $(THEOS_MAKE_PATH)/tweak.mk
