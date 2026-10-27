#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
extern "C" char *omabridge_mobile_call(const uint8_t *, size_t);
extern "C" void omabridge_mobile_free(char *);
#ifndef OMABRIDGE_JNI_CALL
#error "Configure the consuming application's JNI symbol at build time"
#endif
extern "C" JNIEXPORT jbyteArray JNICALL
OMABRIDGE_JNI_CALL(JNIEnv *env, jobject, jbyteArray request) {
    if (!request || env->GetArrayLength(request)>1024*1024) return nullptr;
    std::vector<uint8_t> input(env->GetArrayLength(request));
    env->GetByteArrayRegion(request,0,input.size(),reinterpret_cast<jbyte*>(input.data()));
    if (env->ExceptionCheck()) return nullptr;
    char *raw=omabridge_mobile_call(input.data(),input.size());
    volatile uint8_t *wipe=input.data(); for(size_t i=0;i<input.size();++i) wipe[i]=0;
    if (!raw) return nullptr;
    auto size=std::strlen(raw);auto result=env->NewByteArray(size);
    if(result) env->SetByteArrayRegion(result,0,size,reinterpret_cast<const jbyte*>(raw));
    omabridge_mobile_free(raw);return result;
}
