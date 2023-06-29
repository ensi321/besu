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

package org.hyperledger.besu.datatypes;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonValue;
import org.apache.tuweni.bytes.Bytes32;

/**
 * A VersionedHash is a Hash that forfeits its most significant byte to indicate the hashing
 * algorithm which was used.
 */
public class VersionedHash {

  private final byte versionId;
  Bytes32 hashish;

  /**
   * Construct a VersionedHash from a Bytes32 value.
   *
   * @param versionId The version id of the hash. 01 for sha256.
   * @param hash The hash value being versioned.
   */
  public VersionedHash(final byte versionId, final Hash hash) {
    if (versionId != 1) {
      throw new IllegalArgumentException("Only supported hash version is 0x01, sha256 hash.");
    }

    this.versionId = versionId;
    this.hashish = hash;
  }

  /**
   * Parse a VersionedHash from a Bytes32 value.
   *
   * @param typedHash raw versioned hash bytes to parse.
   */
  public VersionedHash(final Bytes32 typedHash) {
    byte versionId = typedHash.get(0);
    if (versionId != 1) {
      throw new IllegalArgumentException("Only supported hash version is 0x01, sha256 hash.");
    }
    this.versionId = versionId;
    this.hashish = typedHash;
  }

  /**
   * Convert it to raw bytes.
   *
   * @return The hash value.
   */
  public Bytes32 toBytes() {
    byte[] bytes = hashish.toArray();
    bytes[0] = versionId;
    return Bytes32.wrap(bytes);
  }

  /**
   * The version id of the hash.
   *
   * @return the version id.
   */
  public byte getVersionId() {
    return versionId;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    VersionedHash that = (VersionedHash) o;
    return getVersionId() == that.getVersionId() && Objects.equals(this.toBytes(), that.toBytes());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getVersionId(), hashish);
  }

  @JsonValue
  @Override
  public String toString() {
    return this.toBytes().toHexString();
  }
}
