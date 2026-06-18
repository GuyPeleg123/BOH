/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#pragma once

#include <stdint.h>
#include "srsran/srsran.h"

#define UL_SNIFFER_MAX_NOF_OFFSET 2

struct SubframeBuffer {
  SubframeBuffer(uint32_t rf_nof_rx_ant);
  SubframeBuffer(const SubframeBuffer&) = delete; //prevent copy
  SubframeBuffer& operator=(const SubframeBuffer&) = delete; //prevent copy
  ~SubframeBuffer();
  const uint32_t rf_nof_rx_ant;
  cf_t *sf_buffer_a[SRSRAN_MAX_PORTS] = {nullptr};
  cf_t *sf_buffer_b[SRSRAN_MAX_PORTS] = {nullptr};
  // Offset-retry scratch for the FFT-window re-FFT pass (PR #4). Each UL decoder
  // instance needs its OWN snapshot/working pair, otherwise the two decoders
  // (antenna A = enb_ul, antenna B = enb_ul_b) race on these buffers when both
  // run in the same subframe. Index [0] = decoder_a's pair, [1] = decoder_b's
  // pair; within each pair, [...][0] is the clean pre-FFT snapshot and [...][1]
  // is the freq-shifted working copy fed to the FFT.
  cf_t *sf_buffer_offset[2][UL_SNIFFER_MAX_NOF_OFFSET] = {{nullptr}};
};
