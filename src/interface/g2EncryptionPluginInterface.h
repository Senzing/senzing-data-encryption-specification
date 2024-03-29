
/**********************************************************************************
© Copyright Senzing, Inc. 2020-2023
The source code for this program is not published or otherwise divested
of its trade secrets, irrespective of what has been deposited with the U.S.
Copyright Office.
**********************************************************************************/


#ifndef G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED
#define G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED


/* encryption interface headers */
#include "g2EncryptionPluginInterface_defs.h"
#include "g2EncryptionPluginInterface_macros.h"


#ifdef __cplusplus
extern "C"
{
#endif


/* appropriately export function headers */
#if defined(_WIN32)
  #define _DLEXPORT __declspec(dllexport)
#else
  #define _DLEXPORT __attribute__ ((visibility ("default")))
#endif


/* Function used to initialize a plugin */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_INIT_PLUGIN;
/* Function used to close a plugin */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_CLOSE_PLUGIN;

/* Function used to retrieve the plugin signature */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_GET_SIGNATURE;
/* Function used to validate the plugin signature compatibility */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_VALIDATE_SIGNATURE_COMPATIBILITY;

/* Function used to encrypt a data value */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD;
/* Function used to decrypt a data value */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD;

/* Function used to encrypt a data value (deterministic methods) */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD_DETERMINISTIC;
/* Function used to decrypt a data value (deterministic methods) */
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD_DETERMINISTIC;


#ifdef __cplusplus
}
#endif


#endif /* header file */

