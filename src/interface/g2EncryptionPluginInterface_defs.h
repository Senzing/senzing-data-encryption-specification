
/**********************************************************************************
© Copyright Senzing, Inc. 2020-2023
The source code for this program is not published or otherwise divested
of its trade secrets, irrespective of what has been deposited with the U.S.
Copyright Office.
**********************************************************************************/

#ifndef G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_DEFS_INCLUDED
#define G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_DEFS_INCLUDED

/* standard C headers */
#include <stddef.h>

/* constants for defining data structures */
#define G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH 1024

/* constants for return codes and error conditions */
#define G2_ENCRYPTION_PLUGIN___SUCCESS 0

#define G2_ENCRYPTION_PLUGIN___SIMPLE_ERROR -1
#define G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR -20
#define G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR -5
#define G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION -30

#ifdef __cplusplus
extern "C"
{
#endif

/* basic data field structures */
struct CParameterTuple
{
  const char* paramName;
  const char* paramValue;
};
struct CParameterList
{
  struct CParameterTuple* paramTuples;
  size_t numParameters;
};

/* Error message data structure */
struct ErrorInfoData
{
  int mErrorOccurred;
  char mErrorMessage[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH];
};


/* the function prototype used to initialize/close a plugin */
typedef int G2EncryptionPluginInitPluginFunc(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginInitPluginFunc* G2EncryptionPluginInitPluginFuncPtr;
typedef int G2EncryptionPluginClosePluginFunc(char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginClosePluginFunc* G2EncryptionPluginClosePluginFuncPtr;

/* the function prototype used verify the plugin signature */
typedef int G2EncryptionPluginGetSignatureFunc(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginGetSignatureFunc* G2EncryptionPluginGetSignatureFuncPtr;
typedef int G2EncryptionPluginValidateSignatureCompatibilityFunc(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginValidateSignatureCompatibilityFunc* G2EncryptionPluginValidateSignatureCompatibilityFuncPtr;

/* function pointer types for encryption/decryption */
typedef int G2EncryptionPluginEncryptDataFieldFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginEncryptDataFieldFunc* G2EncryptionPluginEncryptDataFieldFuncPtr;
typedef int G2EncryptionPluginDecryptDataFieldFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginDecryptDataFieldFunc* G2EncryptionPluginDecryptDataFieldFuncPtr;

/* function pointer types for encryption/decryption with deterministic behavior */
typedef int G2EncryptionPluginEncryptDataFieldDeterministicFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginEncryptDataFieldDeterministicFunc* G2EncryptionPluginEncryptDataFieldDeterministicFuncPtr;
typedef int G2EncryptionPluginDecryptDataFieldDeterministicFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
typedef G2EncryptionPluginDecryptDataFieldDeterministicFunc* G2EncryptionPluginDecryptDataFieldDeterministicFuncPtr;

#ifdef __cplusplus
}
#endif

#endif /* header file */

