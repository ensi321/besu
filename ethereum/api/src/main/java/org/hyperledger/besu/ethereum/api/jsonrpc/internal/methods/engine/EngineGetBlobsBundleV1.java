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

package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods.engine;

import org.hyperledger.besu.consensus.merge.blockcreation.MergeMiningCoordinator;
import org.hyperledger.besu.consensus.merge.blockcreation.PayloadIdentifier;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.RpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.BlobsBundleV1;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.BlockResultFactory;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockWithReceipts;
import org.hyperledger.besu.ethereum.core.Transaction;

import java.util.List;

import io.vertx.core.Vertx;

public class EngineGetBlobsBundleV1 extends AbstractEngineGetPayload {

  public EngineGetBlobsBundleV1(
      final Vertx vertx,
      final ProtocolContext protocolContext,
      final MergeMiningCoordinator mergeMiningCoordinator,
      final BlockResultFactory blockResultFactory,
      final EngineCallListener engineCallListener) {
    // final ProtocolSchedule schedule) {
    super(vertx, protocolContext, mergeMiningCoordinator, blockResultFactory, engineCallListener);
    // schedule);
  }

  @Override
  protected JsonRpcResponse createResponse(
      final JsonRpcRequestContext request,
      final PayloadIdentifier payloadId,
      final BlockWithReceipts blockWithReceipts) {

    return new JsonRpcSuccessResponse(
        request.getRequest().getId(), createResponse(blockWithReceipts.getBlock()));
  }

  private BlobsBundleV1 createResponse(final Block block) {

    final List<Transaction> transactions = block.getBody().getTransactions();

    return new BlobsBundleV1(transactions);
  }

  @Override
  public String getName() {
    return RpcMethod.ENGINE_GET_BLOBS_BUNDLE_V1.getMethodName();
  }
}
