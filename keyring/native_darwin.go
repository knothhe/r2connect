//go:build darwin && cgo

package keyring

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static NSMutableDictionary *keyringSecretQuery(const char *service, const char *key) {
 return [NSMutableDictionary dictionaryWithDictionary:@{
  (id)kSecClass: (id)kSecClassGenericPassword,
  (id)kSecAttrService: [NSString stringWithUTF8String:service],
  (id)kSecAttrAccount: [NSString stringWithUTF8String:key]
 }];
}

static int keyringSecretLoad(const char *service, const char *key, void **bytes, size_t *size) {
 @autoreleasepool {
  NSMutableDictionary *query = keyringSecretQuery(service, key);
  query[(id)kSecReturnData] = @YES;
  query[(id)kSecMatchLimit] = (id)kSecMatchLimitOne;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
  if (status != errSecSuccess) return (int)status;
  if (!result || CFGetTypeID(result) != CFDataGetTypeID()) {
   if (result) CFRelease(result);
   return (int)errSecDecode;
  }
  CFDataRef data = (CFDataRef)result;
  CFIndex length = CFDataGetLength(data);
  if (length <= 0 || length > 65536) { CFRelease(result); return (int)errSecDecode; }
  *bytes = malloc((size_t)length);
  if (!*bytes) { CFRelease(result); return (int)errSecAllocate; }
  *size = (size_t)length;
  memcpy(*bytes, CFDataGetBytePtr(data), (size_t)length);
  CFRelease(result);
  return (int)errSecSuccess;
 }
}

// Keychain Access shows the label; lookups use only service and account.
static int keyringSecretSave(const char *service, const char *key, const char *label, const void *bytes, size_t size) {
 @autoreleasepool {
  NSMutableDictionary *query = keyringSecretQuery(service, key);
  NSData *data = [NSData dataWithBytes:bytes length:size];
  OSStatus status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)@{(id)kSecValueData: data});
  if (status == errSecItemNotFound) {
   query[(id)kSecValueData] = data;
   NSString *name = [NSString stringWithUTF8String:label];
   if (name) query[(id)kSecAttrLabel] = name;
   status = SecItemAdd((CFDictionaryRef)query, NULL);
   // Another instance may have added this exact item between update and add.
   if (status == errSecDuplicateItem) {
    [query removeObjectForKey:(id)kSecValueData];
    [query removeObjectForKey:(id)kSecAttrLabel];
    status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)@{(id)kSecValueData: data});
   }
  }
  return (int)status;
 }
}

static int keyringSecretDelete(const char *service, const char *key) {
 @autoreleasepool { return (int)SecItemDelete((CFDictionaryRef)keyringSecretQuery(service, key)); }
}

static void keyringSecretFree(void *bytes, size_t size) {
 if (bytes) { memset_s(bytes, size, 0, size); free(bytes); }
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// ErrStoreMissing reports that this account has no usable credential store.
var ErrStoreMissing = errors.New("No macOS keychain is available. Restore the login keychain in Keychain Access, then retry.")

type nativeBackend struct{ label string }

// Native returns the Keychain backend; label names saved items.
func Native(label string) Backend { return nativeBackend{label} }

func keychainError(operation string, status C.int) error {
	if status == C.errSecItemNotFound {
		return ErrNotFound
	}
	if status == C.errSecUserCanceled || status == C.errSecAuthFailed || status == C.errSecInteractionNotAllowed {
		return ErrAccessDenied
	}
	if status == C.errSecNotAvailable || status == C.errSecNoSuchKeychain || status == C.errSecNoDefaultKeychain {
		return ErrStoreMissing
	}
	return fmt.Errorf("macOS Keychain could not %s credentials (status %d)", operation, int(status))
}

func (nativeBackend) Load(service, key string) ([]byte, error) {
	serviceC, keyC := C.CString(service), C.CString(key)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(keyC))
	var bytes unsafe.Pointer
	var size C.size_t
	status := C.keyringSecretLoad(serviceC, keyC, &bytes, &size)
	if status != C.errSecSuccess {
		return nil, keychainError("read", status)
	}
	defer C.keyringSecretFree(bytes, size)
	return C.GoBytes(bytes, C.int(size)), nil
}

func (b nativeBackend) Save(service, key string, value []byte) error {
	serviceC, keyC, labelC := C.CString(service), C.CString(key), C.CString(b.label)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(keyC))
	defer C.free(unsafe.Pointer(labelC))
	status := C.keyringSecretSave(serviceC, keyC, labelC, unsafe.Pointer(&value[0]), C.size_t(len(value)))
	if status != C.errSecSuccess {
		return keychainError("save", status)
	}
	return nil
}

func (nativeBackend) Delete(service, key string) error {
	serviceC, keyC := C.CString(service), C.CString(key)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(keyC))
	status := C.keyringSecretDelete(serviceC, keyC)
	if status != C.errSecSuccess {
		return keychainError("delete", status)
	}
	return nil
}
