#include <jni.h>
#include <cstring>

namespace {
jclass app_class;
jmethodID instance, config_for_host, ct, size, get, certificates;
jfieldID anchors, source;

jint count(JNIEnv *env, jobject collection) {
    return env->CallIntMethod(collection, size);
}
}

// Read the real application config. This library never builds or modifies a config.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_kiber_tuc_probe_ProbeActivity_inspect(JNIEnv *env, jclass) {
    jint result[] = {-1, -1, -1, -1};
    jobject app = env->CallStaticObjectMethod(app_class, instance);
    if (!app || env->ExceptionCheck()) return nullptr;
    jobject config = env->CallObjectMethod(app, config_for_host, nullptr);
    if (!config || env->ExceptionCheck()) return nullptr;
    if (ct) result[0] = env->CallBooleanMethod(config, ct);
    jobject refs = env->GetObjectField(config, anchors);
    if (!refs || env->ExceptionCheck()) return nullptr;
    auto class_class = env->FindClass("java/lang/Class");
    auto get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    const jint length = count(env, refs);
    for (jint i = 0; i < length && !env->ExceptionCheck(); ++i) {
        auto ref = env->CallObjectMethod(refs, get, i);
        auto store = env->GetObjectField(ref, source);
        auto cls = env->GetObjectClass(store);
        auto name = static_cast<jstring>(env->CallObjectMethod(cls, get_name));
        if (env->ExceptionCheck()) return nullptr;
        const char *text = env->GetStringUTFChars(name, nullptr);
        if (!text) return nullptr;
        int slot = 3;
        // Source presence is reported even when its certificate store is empty.
        if (strcmp(text, "android.security.net.config.SystemCertificateSource") == 0) slot = 1;
        if (strcmp(text, "android.security.net.config.UserCertificateSource") == 0) slot = 2;
        env->ReleaseStringUTFChars(name, text);
        auto certs = env->CallObjectMethod(store, certificates);
        if (!certs || env->ExceptionCheck()) return nullptr;
        if (result[slot] < 0) result[slot] = 0;
        result[slot] += count(env, certs);
        env->DeleteLocalRef(certs);
        env->DeleteLocalRef(name);
        env->DeleteLocalRef(cls);
        env->DeleteLocalRef(store);
        env->DeleteLocalRef(ref);
    }
    if (env->ExceptionCheck()) return nullptr;
    auto output = env->NewIntArray(4);
    if (output) env->SetIntArrayRegion(output, 0, 4, result);
    return output;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    auto app = env->FindClass("android/security/net/config/ApplicationConfig");
    auto config = env->FindClass("android/security/net/config/NetworkSecurityConfig");
    auto ref = env->FindClass("android/security/net/config/CertificatesEntryRef");
    auto store = env->FindClass("android/security/net/config/CertificateSource");
    auto list = env->FindClass("java/util/List");
    auto collection = env->FindClass("java/util/Collection");
    if (!app || !config || !ref || !store || !list || !collection) return JNI_ERR;
    app_class = static_cast<jclass>(env->NewGlobalRef(app));
    instance = env->GetStaticMethodID(app, "getDefaultInstance", "()Landroid/security/net/config/ApplicationConfig;");
    config_for_host = env->GetMethodID(app, "getConfigForHostname", "(Ljava/lang/String;)Landroid/security/net/config/NetworkSecurityConfig;");
    anchors = env->GetFieldID(config, "mCertificatesEntryRefs", "Ljava/util/List;");
    source = env->GetFieldID(ref, "mSource", "Landroid/security/net/config/CertificateSource;");
    certificates = env->GetMethodID(store, "getCertificates", "()Ljava/util/Set;");
    size = env->GetMethodID(collection, "size", "()I");
    get = env->GetMethodID(list, "get", "(I)Ljava/lang/Object;");
    if (env->ExceptionCheck() || !app_class || !instance || !config_for_host || !anchors || !source || !certificates || !size || !get) return JNI_ERR;
    ct = env->GetMethodID(config, "isCertificateTransparencyVerificationRequired", "()Z");
    if (env->ExceptionCheck()) { env->ExceptionClear(); ct = nullptr; }
    return JNI_VERSION_1_6;
}
