LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= trampoline_encmnt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)
LOCAL_SHARED_LIBRARIES := libcryptfslollipop libcutils libe4crypt libwifikeystorehal libsoftkeymasterdevice android.system.wifi.keystore@1.0
LOCAL_STATIC_LIBRARIES := libmultirom_static libext4_utils

LOCAL_ADDITIONAL_DEPENDENCIES += libstdc++

ifeq ($(TARGET_HW_DISK_ENCRYPTION),true)
    LOCAL_ADDITIONAL_DEPENDENCIES += libcryptfs_hw
endif

MR_NO_KEXEC_MK_OPTIONS := true 1 allowed 2 enabled 3 ui_confirm 4 ui_choice 5 forced
ifneq (,$(filter $(MR_NO_KEXEC), $(MR_NO_KEXEC_MK_OPTIONS)))
    LOCAL_STATIC_LIBRARIES +=libbootimg
endif

LOCAL_WHOLE_STATIC_LIBRARIES := libm libpng libz libft2_mrom_static

ifneq ($(wildcard bootable/recovery/crypto/fde/cryptfs.h),)
    mr_twrp_path := bootable/recovery
else ifneq ($(wildcard bootable/recovery-twrp/crypto/fde/cryptfs.h),)
    mr_twrp_path := bootable/recovery-twrp
else
    $(error Failed to find path to TWRP, which is required to build MultiROM with encryption support)
endif

LOCAL_C_INCLUDES += $(multirom_local_path) $(mr_twrp_path) $(mr_twrp_path)/crypto/scrypt/lib/crypto $(mr_twrp_path)/crypto/ext4crypt external/openssl/include external/boringssl/include
LOCAL_C_INCLUDES += system/extras/libbootimg/include
LOCAL_C_INCLUDES += system/extras/ext4_utils/include/ext4_utils

LOCAL_SRC_FILES := \
    encmnt.cpp \
    pw_ui.cpp \
    ../rom_quirks.c \
    ../rq_inject_file_contexts.c \

include $(multirom_local_path)/device_defines.mk

include $(BUILD_EXECUTABLE)


ifeq ($(MR_ENCRYPTION_FAKE_PROPERTIES),true)
    include $(CLEAR_VARS)

    LOCAL_MODULE := libmultirom_fake_properties
    LOCAL_MODULE_TAGS := optional
    LOCAL_C_INCLUDES += $(multirom_local_path)
	LOCAL_C_INCLUDES += system/extras/libbootimg/include

    LOCAL_SRC_FILES := fake_properties.c
    LOCAL_SHARED_LIBRARIES := liblog

    ifneq ($(MR_ENCRYPTION_FAKE_PROPERTIES_EXTRAS),)
        LOCAL_CFLAGS += -DMR_ENCRYPTION_FAKE_PROPERTIES_EXTRAS
        LOCAL_SRC_FILES += ../../../../$(MR_ENCRYPTION_FAKE_PROPERTIES_EXTRAS)
    endif

    include $(multirom_local_path)/device_defines.mk

    include $(BUILD_SHARED_LIBRARY)

    include $(CLEAR_VARS)

    LOCAL_MODULE := libmultirom_fake_propertywait
    LOCAL_MODULE_TAGS := optional
    LOCAL_C_INCLUDES += $(multirom_local_path)

    LOCAL_SRC_FILES := property_wait.cpp

    include $(multirom_local_path)/device_defines.mk

    include $(BUILD_SHARED_LIBRARY)
endif
