/**
 * @defgroup    cose_cryto_sodium Crypto glue layer, sodium definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for gluing AES-CCM. Works on both:
 * - x86 when compiled with -msse2 -msse -march=native -maes
 * - ESP32 with ESP-IDF, which sets the ESP_PLATFORM definition
 * @{
 *
 * @file
 * @brief       Crypto function api for gluing AES-CCM.
 *
 * @author      Marco vR
 */

#ifndef LIBCOSE_TC_AES_H
#define LIBCOSE_TC_AES_H

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_AES128CCM
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* LIBCOSE_TC_AES_H */
/** @} */
