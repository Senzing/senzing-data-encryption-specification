
/**********************************************************************************
© Copyright Senzing, Inc. 2020-2023
The source code for this program is not published or otherwise divested
of its trade secrets, irrespective of what has been deposited with the U.S.
Copyright Office.
**********************************************************************************/

#ifndef G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED
#define G2_ENCRYPTION_PLUGIN_INTERFACE_HEADER_INCLUDED

#include "g2EncryptionPluginInterface_defs.h"
#include "g2EncryptionPluginInterface_macros.h"

#if defined(_WIN32)
  #define _DLEXPORT __declspec(dllexport)
#else
  #define _DLEXPORT __attribute__ ((visibility ("default")))
#endif

_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_INIT_PLUGIN;
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_CLOSE_PLUGIN;

_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_GET_SIGNATURE;
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_VALIDATE_SIGNATURE_COMPATIBILITY;

_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD;
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD;

_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_ENCRYPT_DATA_FIELD_DETERMINISTIC;
_DLEXPORT G2_ENCRYPTION_PLUGIN_FUNCTION_DECRYPT_DATA_FIELD_DETERMINISTIC;

#endif /* header file */

