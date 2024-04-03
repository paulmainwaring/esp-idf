/*
 * SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <stdbool.h>
#include "sdkconfig.h"
#include "esp_sleep.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Enables the use of ADC and temperature sensor in monitor (ULP) mode
 *
 * @note  This state is kept in RTC memory and will keep its value after a deep sleep wakeup
 *
 */
void esp_sleep_enable_adc_tsens_monitor(bool enable);

#if !SOC_GPIO_SUPPORT_HOLD_SINGLE_IO_IN_DSLP
/**
 * @brief Isolate all digital IOs except those that are held during deep sleep
 *
 * Reduce digital IOs current leakage during deep sleep.
 */
void esp_sleep_isolate_digital_gpio(void);
#endif

/**
  * Register a callback to be called from the deep sleep prepare for maintain the PHY state
  *          CPU is equal to min_freq_mhz (if DFS is enabled) when running this callback,
  *          and PLL clock is exists)
  *
  * @warning deepsleep PHY callbacks should without parameters, and MUST NOT,
  *          UNDER ANY CIRCUMSTANCES, CALL A FUNCTION THAT MIGHT BLOCK.
  *
  * @param new_dslp_cb     Callback to be called to close PHY related modules
  *
  * @return
  *     - ESP_OK:         PHY callback registered to the phy modules deepsleep prepare
  *     - ESP_ERR_NO_MEM: No more hook space for register the callback
  */
esp_err_t esp_deep_sleep_register_phy_hook(esp_deep_sleep_cb_t new_dslp_cb);

/**
  * @brief Unregister an PHY deepsleep callback
  *
  * @param old_dslp_cb     Callback to be unregistered
  */
void esp_deep_sleep_deregister_phy_hook(esp_deep_sleep_cb_t old_dslp_cb);

#ifdef __cplusplus
}
#endif
