
/**********************************************************************************
© Copyright Senzing, Inc. 2020-2021
The source code for this program is not published or otherwise divested
of its trade secrets, irrespective of what has been deposited with the U.S.
Copyright Office.
**********************************************************************************/

#ifndef G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED
#define G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED

/* standard C++ headers */
#include <stddef.h>
#include <string.h>
#include <stdbool.h>


/* constants for defining data structures */
#define G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH 1024

/* constants for return codes and error conditions */
#define G2_ENCRYPTION_PLUGIN___SUCCESS 0
#define G2_ENCRYPTION_PLUGIN___SUCCESS_WITH_INFO 1
#define G2_ENCRYPTION_PLUGIN___SIMPLE_ERROR -1
#define G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR -20
#define G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR -5
#define G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION -30


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


/* @def the function header for initPlugin (can't use typedef) */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_INIT_PLUGIN int G2Encryption_InitPlugin(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize)
#define G2_ENCRYPTION_PLUGIN_FUNCTION_CLOSE_PLUGIN int G2Encryption_ClosePlugin(char *error, const size_t maxErrorSize, size_t* errorSize)

#define G2_ENCRYPTION_PLUGIN_FUNCTION_GET_SIGNATURE int G2Encryption_GetSignature(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize)
#define G2_ENCRYPTION_PLUGIN_FUNCTION_VALIDATE_SIGNATURE_COMPATIBILITY int G2Encryption_ValidateSignatureCompatibility(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize)

#define G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD int G2Encryption_EncryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)
#define G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD int G2Encryption_DecryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)



/**
@def a macro which must be placed inside the init-plugin function, to prime the funcion
*/
#define INIT_PLUGIN_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData initializationErrorData; \
initializationErrorData.mErrorOccurred = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the init-plugin function, to finialize the funcion
*/
#define INIT_PLUGIN_FUNCTION_POSTAMBLE \
/* prepare response */ \
if (initializationErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Data encryption plugin initialization error occurred: '"); \
  strcat(errorText,initializationErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
return retVal;


/**
@def a macro which must be placed inside the close-plugin function, to prime the funcion
*/
#define CLOSE_PLUGIN_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData finalizationErrorData; \
finalizationErrorData.mErrorOccurred = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the close-plugin function, to finialize the funcion
*/
#define CLOSE_PLUGIN_FUNCTION_POSTAMBLE \
/* prepare response */ \
if (finalizationErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Data encryption plugin finalization error occurred: '"); \
  strcat(errorText,finalizationErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
return retVal;


/**
@def a macro which must be placed inside the encrypt function, to prime the funcion
*/
#define ENCRYPT_DATA_FIELD_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData encryptionErrorData; \
encryptionErrorData.mErrorOccurred = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;

/**
@def a macro which must be placed inside the encrypt function, to finialize the funcion
*/
#define ENCRYPT_DATA_FIELD_FUNCTION_POSTAMBLE \
/* prepare response */ \
if (encryptionErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Data encryption error occurred: '"); \
  strcat(errorText,encryptionErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
else if (resultSizeErrorOccurred) \
{ \
  const char* errorText = "Return size exceeds maximum allowed size"; \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR; \
} \
return retVal;


/**
@def a macro which must be placed inside the decrypt function, to prime the funcion
*/
#define DECRYPT_DATA_FIELD_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData decryptionErrorData; \
decryptionErrorData.mErrorOccurred = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;

/**
@def a macro which must be placed inside the decrypt function, to finialize the funcion
*/
#define DECRYPT_DATA_FIELD_FUNCTION_POSTAMBLE \
/* prepare response */ \
if (decryptionErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Data decryption error occurred: '"); \
  strcat(errorText,decryptionErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
else if (resultSizeErrorOccurred) \
{ \
  const char* errorText = "Return size exceeds maximum allowed size"; \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR; \
} \
return retVal;


/**
@def a macro which must be placed inside the get-signature function, to prime the funcion
*/
#define GET_SIGNATURE_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData getSignatureErrorData; \
getSignatureErrorData.mErrorOccurred = 0; \
bool signatureSizeErrorOccurred = false; \
*signatureSize = 0; \
*errorSize = 0;

/**
@def a macro which must be placed inside the get-signature function, to finialize the funcion
*/
#define GET_SIGNATURE_FUNCTION_POSTAMBLE \
/* prepare response */ \
if (getSignatureErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Error occurred while getting encryption signature: '"); \
  strcat(errorText,getSignatureErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
if (signatureSizeErrorOccurred) \
{ \
  const char* errorText = "Return size exceeds maximum allowed size"; \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR; \
} \
return retVal;


/**
@def a macro which must be placed inside the validate-signature-compatibility function, to prime the funcion
*/
#define VALIDATE_SIGNATURE_COMPATIBILITY_FUNCTION_PREAMBLE \
/* set up base variables */ \
int retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData validationErrorData; \
validationErrorData.mErrorOccurred = 0; \
bool signatureIsCompatible = false; \
*errorSize = 0;


/**
@def a macro which must be placed inside the validate-signature-compatibility function, to finialize the funcion
*/
#define VALIDATE_SIGNATURE_COMPATIBILITY_FUNCTION_POSTAMBLE \
if (validationErrorData.mErrorOccurred) \
{ \
  char errorText[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH]; \
  errorText[0] = '\0'; \
  strcat(errorText,"Error occurred doing encryption signature validation: '"); \
  strcat(errorText,validationErrorData.mErrorMessage); \
  strcat(errorText,"'"); \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR; \
} \
else if (!signatureIsCompatible) \
{ \
  const char* errorText = "Encryption signature is not compatible"; \
  strncpy(error, errorText, maxErrorSize); \
  error[maxErrorSize - 1] = '\0'; \
  *errorSize = strlen(errorText); \
  retVal = G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION; \
} \
return retVal;


#endif /* header file */

