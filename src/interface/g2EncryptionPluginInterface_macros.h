
/**********************************************************************************
© Copyright Senzing, Inc. 2023-2025
The source code for this program is not published or otherwise divested
of its trade secrets, irrespective of what has been deposited with the U.S.
Copyright Office.
**********************************************************************************/


#ifndef G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_MACROS_INCLUDED
#define G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_MACROS_INCLUDED


#include "g2EncryptionPluginInterface_defs.h"
#include <string.h>
#include <stdbool.h>


/*
 * Function prototype definitions
 */


/* Function used to initialize a plugin
 *
 * @param configParams A set of configuration parameters
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_INIT_PLUGIN int64_t G2Encryption_InitPlugin(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize)

/* Function used to close a plugin
 *
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_CLOSE_PLUGIN int64_t G2Encryption_ClosePlugin(char *error, const size_t maxErrorSize, size_t* errorSize)


/* Function used to retrieve the plugin signature
 *
 * This function retrieves the signature of the encryption plugin.  This signature is stored in
 * the datastore, and verified during system startup, to ensure that the encyption is consistent.
 *
 * @param signature A buffer through which the plugin signature may be returned
 * @param maxSignatureSize The maximum size of the signature buffer
 * @param signatureSize The size of a signature put into the signature buffer
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_GET_SIGNATURE int64_t G2Encryption_GetSignature(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize)

/* Function used to validate the plugin signature compatibility
 *
 * This function return the SUCCESS return code if the signature compatibility is successfully
 * validated against the known system encryption signature.
 *
 * @param signatureToValidate A plugin signature to be validated
 * @param signatureToValidateSize The size of the plugin signature to be validated
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_VALIDATE_SIGNATURE_COMPATIBILITY int64_t G2Encryption_ValidateSignatureCompatibility(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize)


/* Function used to encrypt a data value
 *
 * This function may use any encryption methodologies, including those with nondeterministic
 * results.
 *
 * @param input A data value to be encrypted
 * @param inputSize The size of the data value to be encrypted
 * @param result A buffer through which the encrypted value may be returned
 * @param maxResultSize The maximum size of the result buffer
 * @param resultSize The size of an result put into the result buffer
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD int64_t G2Encryption_EncryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)

/* Function used to decrypt a data value
 *
 * This function may use any encryption methodologies, including those with nondeterministic
 * results.
 *
 * @param input A data value to be decrypted
 * @param inputSize The size of the data value to be decrypted
 * @param result A buffer through which the decrypted value may be returned
 * @param maxResultSize The maximum size of the result buffer
 * @param resultSize The size of an result put into the result buffer
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD int64_t G2Encryption_DecryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)


/* Function used to encrypt a data value (deterministic methods)
 *
 * This function may only use encryption methodologies that are deterministic.
 * (i.e. any input value to be encryped/decrypted results in a single, consistent result.
 *
 * @param input A data value to be encrypted
 * @param inputSize The size of the data value to be encrypted
 * @param result A buffer through which the encrypted value may be returned
 * @param maxResultSize The maximum size of the result buffer
 * @param resultSize The size of an result put into the result buffer
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD_DETERMINISTIC int64_t G2Encryption_EncryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)

/* Function used to decrypt a data value (deterministic methods)
 *
 * This function may only use encryption methodologies that are deterministic.
 * (i.e. any input value to be encryped/decrypted results in a single, consistent result.
 *
 * @param input A data value to be decrypted
 * @param inputSize The size of the data value to be decrypted
 * @param result A buffer through which the decrypted value may be returned
 * @param maxResultSize The maximum size of the result buffer
 * @param resultSize The size of an result put into the result buffer
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
#define G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD_DETERMINISTIC int64_t G2Encryption_DecryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize)



/*
 * Function definition preamble/postamble macros
 */


/**
@def a macro which must be placed inside the init-plugin function, to prime the function
*/
#define INIT_PLUGIN_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData initializationErrorData; \
initializationErrorData.mErrorOccurred = 0; \
initializationErrorData.mErrorMessage[0] = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the init-plugin function, to finalize the function
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
@def a macro which must be placed inside the close-plugin function, to prime the function
*/
#define CLOSE_PLUGIN_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData finalizationErrorData; \
finalizationErrorData.mErrorOccurred = 0; \
finalizationErrorData.mErrorMessage[0] = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the close-plugin function, to finalize the function
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
@def a macro which must be placed inside the encrypt function, to prime the function
*/
#define ENCRYPT_DATA_FIELD_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData encryptionErrorData; \
encryptionErrorData.mErrorOccurred = 0; \
encryptionErrorData.mErrorMessage[0] = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the encrypt function, to finalize the function
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
@def a macro which must be placed inside the decrypt function, to prime the function
*/
#define DECRYPT_DATA_FIELD_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData decryptionErrorData; \
decryptionErrorData.mErrorOccurred = 0; \
decryptionErrorData.mErrorMessage[0] = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the decrypt function, to finalize the function
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
@def a macro which must be placed inside the encrypt function, to prime the function
*/
#define ENCRYPT_DATA_FIELD_DETERMINISTIC_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData encryptionErrorData; \
encryptionErrorData.mErrorOccurred = 0; \
encryptionErrorData.mErrorMessage[0] = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the encrypt function, to finalize the function
*/
#define ENCRYPT_DATA_FIELD_DETERMINISTIC_FUNCTION_POSTAMBLE \
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
@def a macro which must be placed inside the decrypt function, to prime the function
*/
#define DECRYPT_DATA_FIELD_DETERMINISTIC_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData decryptionErrorData; \
decryptionErrorData.mErrorOccurred = 0; \
decryptionErrorData.mErrorMessage[0] = 0; \
bool resultSizeErrorOccurred = false; \
*resultSize = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the decrypt function, to finalize the function
*/
#define DECRYPT_DATA_FIELD_DETERMINISTIC_FUNCTION_POSTAMBLE \
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
@def a macro which must be placed inside the get-signature function, to prime the function
*/
#define GET_SIGNATURE_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData getSignatureErrorData; \
getSignatureErrorData.mErrorOccurred = 0; \
getSignatureErrorData.mErrorMessage[0] = 0; \
bool signatureSizeErrorOccurred = false; \
*signatureSize = 0; \
*errorSize = 0;


/**
@def a macro which must be placed inside the get-signature function, to finalize the function
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
@def a macro which must be placed inside the validate-signature-compatibility function, to prime the function
*/
#define VALIDATE_SIGNATURE_COMPATIBILITY_FUNCTION_PREAMBLE \
/* set up base variables */ \
int64_t retVal = G2_ENCRYPTION_PLUGIN___SUCCESS; \
struct ErrorInfoData validationErrorData; \
validationErrorData.mErrorOccurred = 0; \
validationErrorData.mErrorMessage[0] = 0; \
bool signatureIsCompatible = false; \
*errorSize = 0;


/**
@def a macro which must be placed inside the validate-signature-compatibility function, to finalize the function
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

