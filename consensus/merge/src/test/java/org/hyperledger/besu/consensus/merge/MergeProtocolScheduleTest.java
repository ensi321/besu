/*
 * Copyright Hyperledger Besu Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.consensus.merge;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.config.GenesisConfigFile;
import org.hyperledger.besu.config.GenesisConfigOptions;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderTestFixture;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.evm.operation.PrevRanDaoOperation;

import org.junit.Test;

public class MergeProtocolScheduleTest {

  @Test
  public void protocolSpecsAreCreatedAtBlockDefinedInJson() {
    final String jsonInput =
        "{\"config\": "
            + "{\"chainId\": 1,\n"
            + "\"homesteadBlock\": 1,\n"
            + "\"LondonBlock\": 1559}"
            + "}";

    final GenesisConfigOptions config = GenesisConfigFile.fromConfig(jsonInput).getConfigOptions();
    final ProtocolSchedule protocolSchedule = MergeProtocolSchedule.create(config, false);

    final ProtocolSpec homesteadSpec = protocolSchedule.getByBlockHeader(blockHeader(1));
    final ProtocolSpec londonSpec = protocolSchedule.getByBlockHeader(blockHeader(1559));

    assertThat(homesteadSpec).isNotEqualTo(londonSpec);
    assertThat(homesteadSpec.getFeeMarket().implementsBaseFee()).isFalse();
    assertThat(londonSpec.getFeeMarket().implementsBaseFee()).isTrue();
  }

  @Test
  public void parametersAlignWithMainnetWithAdjustments() {
    final ProtocolSpec london =
        MergeProtocolSchedule.create(GenesisConfigFile.DEFAULT.getConfigOptions(), false)
            .getByBlockHeader(blockHeader(0));

    assertThat(london.getName()).isEqualTo("Frontier");
    assertThat(london.getBlockReward()).isEqualTo(Wei.ZERO);
    assertThat(london.isSkipZeroBlockRewards()).isTrue();

    var op = london.getEvm().getOperationsUnsafe()[0x44];
    assertThat(op).isInstanceOf(PrevRanDaoOperation.class);
  }

  private BlockHeader blockHeader(final long number) {
    return new BlockHeaderTestFixture().number(number).buildHeader();
  }
}
