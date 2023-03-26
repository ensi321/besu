/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.chainimport.internal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.apache.tuweni.units.bigints.UInt64;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BLSPublicKey;
import org.hyperledger.besu.datatypes.BLSSignature;
import org.hyperledger.besu.datatypes.GWei;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Deposit;
import org.hyperledger.besu.ethereum.core.Transaction;

import java.util.Optional;

/** The Transaction data. */
@JsonIgnoreProperties("comment")
public class DepositData {
  private final BLSPublicKey pubKey;
  private final Bytes32 depositWithdrawalCredentials;
  private final GWei amount;
  private final BLSSignature signature;
  private final UInt64 index;

  @JsonCreator
  public DepositData(
      @JsonProperty("pubKey") final String pubKey,
      @JsonProperty("withdrawalCredential") final String withdrawalCredential,
      @JsonProperty("amount") final String amount,
      @JsonProperty("signature") final String signature,
      @JsonProperty("index") final String index) {

    this.pubKey = BLSPublicKey.fromHexString(pubKey);
    this.depositWithdrawalCredentials = Bytes32.fromHexString(withdrawalCredential);
    this.amount = GWei.fromHexString(amount);
    this.signature = BLSSignature.fromHexString(signature);
    this.index = UInt64.fromHexString(index);

  }


  public Deposit toDeposit() {
    return new Deposit(pubKey, depositWithdrawalCredentials, amount, signature, index);
  }

}
