LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	app_main.cpp \
  xposed_safemode.cpp \
  xposed.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
	liblog \
	libbinder \
	libandroid_runtime \
  libdvm \
  libstlport \
  libdl \
  libandroidfw

LOCAL_C_INCLUDES += dalvik \
                    dalvik/vm \
                    external/stlport/stlport \
                    bionic \
                    bionic/libstdc++/include

LOCAL_CFLAGS += -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION)

ifeq ($(strip $(WITH_JIT)),true)
  LOCAL_CFLAGS += -DWITH_JIT
endif

ifeq ($(strip $(XPOSED_SHOW_OFFSETS)),true)
  LOCAL_CFLAGS += -DXPOSED_SHOW_OFFSETS
endif

LOCAL_MODULE:= app_process

include $(BUILD_EXECUTABLE)


# Build a variant of app_process binary linked with ASan runtime.
# ARM-only at the moment.
ifeq ($(TARGET_ARCH),arm)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	app_main.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
	liblog \
	libbinder \
	libandroid_runtime

LOCAL_MODULE := app_process__asan
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)/asan
LOCAL_MODULE_STEM := app_process
LOCAL_ADDRESS_SANITIZER := true

include $(BUILD_EXECUTABLE)

endif # ifeq($(TARGET_ARCH),arm)
