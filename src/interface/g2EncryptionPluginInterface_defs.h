
/**********************************************************************************
© Copyright Senzing, Inc. 2023
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


/*
 * constants for return codes and error conditions
 */

/* Return code for successful completion */
#define G2_ENCRYPTION_PLUGIN___SUCCESS 0
/* Return code for a simple error, which can be overlooked */
#define G2_ENCRYPTION_PLUGIN___SIMPLE_ERROR -1
/* Return code for a critical error, which should cause a system shutdown */
#define G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR -20
/* Return code for the output buffer being too small  */
#define G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR -5
/* Return code for failing the signature validation of an encryption plugin */
#define G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION -30


#ifdef __cplusplus
extern "C"
{
#endif


/*
 * basic data information structures
 */


/* data parameter value */
struct CParameterTuple
{
  /* parameter name */
  const char* paramName;
  /* parameter value */
  const char* paramValue;
};


/* list of data parameter values */
struct CParameterList
{
  /* pointer to array of paramters */
  struct CParameterTuple* paramTuples;
  /* number of parameters in array */
  size_t numParameters;
};


/* Error message data structure */
struct ErrorInfoData
{
  /* boolean value indicating if an error occurred */
  int mErrorOccurred;
  /* error description message */
  char mErrorMessage[G2_ENCRYPTION_PLUGIN___MAX_ERROR_MESSAGE_LENGTH];
};


/*
 * Function type definitions
 */


/* @brief Function prototype used to initialize a plugin
 *
 * @param configParams A set of configuration parameters
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
typedef int G2EncryptionPluginInitPluginFunc(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to initialize a plugin */
typedef G2EncryptionPluginInitPluginFunc* G2EncryptionPluginInitPluginFuncPtr;



/* @brief Function prototype used to close a plugin
 *
 * @param error A buffer through which error messages may be returned
 * @param maxErrorSize The maximum size of the error buffer
 * @param errorSize The size of an error message put into the error buffer
 * @return success/failure return code
 */
typedef int G2EncryptionPluginClosePluginFunc(char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to close a plugin */
typedef G2EncryptionPluginClosePluginFunc* G2EncryptionPluginClosePluginFuncPtr;



/* @brief Function prototype used to retrieve the plugin signature
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
typedef int G2EncryptionPluginGetSignatureFunc(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to retrieve the plugin signature */
typedef G2EncryptionPluginGetSignatureFunc* G2EncryptionPluginGetSignatureFuncPtr;



/* @brief Function prototype used to validate the plugin signature compatibility
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
typedef int G2EncryptionPluginValidateSignatureCompatibilityFunc(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to validate the plugin signature compatibility */
typedef G2EncryptionPluginValidateSignatureCompatibilityFunc* G2EncryptionPluginValidateSignatureCompatibilityFuncPtr;



/* @brief Function prototype used to encrypt a data value
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
typedef int G2EncryptionPluginEncryptDataFieldFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to encrypt a data value */
typedef G2EncryptionPluginEncryptDataFieldFunc* G2EncryptionPluginEncryptDataFieldFuncPtr;



/* @brief Function prototype used to decrypt a data value
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
typedef int G2EncryptionPluginDecryptDataFieldFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to decrypt a data value */
typedef G2EncryptionPluginDecryptDataFieldFunc* G2EncryptionPluginDecryptDataFieldFuncPtr;



/* @brief Function prototype used to encrypt a data value (deterministic methods)
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
typedef int G2EncryptionPluginEncryptDataFieldDeterministicFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to encrypt a data value */
typedef G2EncryptionPluginEncryptDataFieldDeterministicFunc* G2EncryptionPluginEncryptDataFieldDeterministicFuncPtr;



/* @brief Function prototype used to decrypt a data value (deterministic methods)
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
typedef int G2EncryptionPluginDecryptDataFieldDeterministicFunc(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);

/* a pointer to the function used to decrypt a data value */
typedef G2EncryptionPluginDecryptDataFieldDeterministicFunc* G2EncryptionPluginDecryptDataFieldDeterministicFuncPtr;


#ifdef __cplusplus
}
#endif


#endif /* header file */

