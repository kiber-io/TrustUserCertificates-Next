LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := trustusercerts
LOCAL_LDLIBS := -ldl -llog
LOCAL_SRC_FILES := module.cpp
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -Werror -fvisibility=hidden -fno-exceptions -fno-rtti -fno-threadsafe-statics
LOCAL_LDFLAGS := -Wl,--gc-sections
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := trustusercerts-diagnostic
LOCAL_LDLIBS := -ldl -llog
LOCAL_SRC_FILES := diagnostic.cpp
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -Werror -fno-exceptions -fno-rtti -fno-threadsafe-statics
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := trustusercerts-protocol-test
LOCAL_SRC_FILES := protocol_test.cpp
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -Werror -fno-exceptions -fno-rtti
include $(BUILD_EXECUTABLE)
