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
package org.hyperledger.besu.ethereum.core.encoding;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.BLSPublicKey;
import org.hyperledger.besu.datatypes.BLSSignature;
import org.hyperledger.besu.datatypes.DepositDepositWithdrawalCredential;
import org.hyperledger.besu.datatypes.GWei;
import org.hyperledger.besu.ethereum.core.Deposit;
import org.hyperledger.besu.ethereum.core.DepositContract;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.hyperledger.besu.evm.log.Log;
import org.web3j.tx.Contract;


public class DepositDecoder {

  public static Deposit decode(final RLPInput rlpInput) {
    rlpInput.enterList();
    final BLSPublicKey publicKey = BLSPublicKey.readFrom(rlpInput);
    final DepositDepositWithdrawalCredential depositWithdrawalCredential =
        DepositDepositWithdrawalCredential.readFrom(rlpInput);
    final GWei amount = GWei.of(rlpInput.readUInt64Scalar());
    final BLSSignature signature = BLSSignature.readFrom(rlpInput);
    final UInt64 index = UInt64.valueOf(rlpInput.readBigIntegerScalar());
    rlpInput.leaveList();

    return new Deposit(publicKey, depositWithdrawalCredential, amount, signature, index);
  }

  public static Deposit decode(final Log log) {
    Contract.EventValuesWithLog eventValues = DepositContract.staticExtractDepositEventWithLog(log);
    byte[] rawPublicKey = (byte[]) eventValues.getNonIndexedValues().get(0).getValue();
    byte[] rawWithdrawalCredential = (byte[]) eventValues.getNonIndexedValues().get(1).getValue();
    byte[] rawSignature = (byte[]) eventValues.getNonIndexedValues().get(2).getValue();
    byte[] rawAmount = (byte[]) eventValues.getNonIndexedValues().get(3).getValue();
    byte[] rawIndex = (byte[]) eventValues.getNonIndexedValues().get(4).getValue();

    return new Deposit(
      BLSPublicKey.wrap(Bytes.wrap(rawPublicKey)),
      DepositDepositWithdrawalCredential.wrap(Bytes.wrap(rawWithdrawalCredential)),
      GWei.of(Bytes.wrap(rawAmount).reverse().toLong()),
      BLSSignature.wrap(Bytes.wrap(rawSignature)),
      UInt64.valueOf(Bytes.wrap(rawIndex).reverse().toLong())
      );
  }

  public static Deposit decodeOpaqueBytes(final Bytes input) {
    return decode(RLP.input(input));
  }
}
