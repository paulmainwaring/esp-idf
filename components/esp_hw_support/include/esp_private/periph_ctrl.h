/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "soc/periph_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enable peripheral module by un-gating the clock and de-asserting the reset signal.
 *
 * @param[in] periph Peripheral module
 *
 * @note If @c periph_module_enable() is called a number of times,
 *       @c periph_module_disable() has to be called the same number of times,
 *       in order to put the peripheral into disabled state.
 */
void periph_module_enable(periph_module_t periph);

/**
 * @brief Disable peripheral module by gating the clock and asserting the reset signal.
 *
 * @param[in] periph Peripheral module
 *
 * @note If @c periph_module_enable() is called a number of times,
 *       @c periph_module_disable() has to be called the same number of times,
 *       in order to put the peripheral into disabled state.
 */
void periph_module_disable(periph_module_t periph);

/**
 * @brief Reset peripheral module by asserting and de-asserting the reset signal.
 *
 * @param[in] periph Peripheral module
 *
 * @note Calling this function does not enable or disable the clock for the module.
 */
void periph_module_reset(periph_module_t periph);

/**
 * @brief Enable Wi-Fi and BT common module
 *
 * @note If @c wifi_bt_common_module_enable() is called a number of times,
 *       @c wifi_bt_common_module_disable() has to be called the same number of times,
 *       in order to put the peripheral into disabled state.
 */
void wifi_bt_common_module_enable(void);

/**
 * @brief Disable Wi-Fi and BT common module
 *
 * @note If @c wifi_bt_common_module_enable() is called a number of times,
 *       @c wifi_bt_common_module_disable() has to be called the same number of times,
 *       in order to put the peripheral into disabled state.
 */
void wifi_bt_common_module_disable(void);

/**
 * @brief Enable Wi-Fi module
 *
 * @note Calling this function will only enable Wi-Fi module.
 */
void wifi_module_enable(void);

/**
 * @brief Disable Wi-Fi module
 *
 * @note Calling this function will only disable Wi-Fi module.
 */
void wifi_module_disable(void);

/**
 * @brief Enable phy module by un-gating related clock and de-asserting the reset signal.
 *
 * @note This function acquires clocks required during the PHY enable sequence.
 */
void phy_module_enable(void);

/**
 * @brief Disable phy module by gating related clock and asserting the reset signal.
 *
 * @note This function releases clocks required during the PHY enable sequence.
 */
void phy_module_disable(void);

/**
 * @brief Checks whether phy module has all bits in @p mask set.
 *
 * @return true if all bits in @p mask are set; false otherwise.
 */
bool phy_module_has_clock_bits(uint32_t mask);

#ifdef __cplusplus
}
#endif
