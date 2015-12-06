package cn.yxffcode.automaton.lucene.util;

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.DataInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Properties;

/**
 * Methods for manipulating strings.
 *
 * @lucene.internal
 */
public abstract class StringHelper {

  private StringHelper() {
  }

  public static boolean equals(String s1, String s2) {
    if (s1 == null) {
      return s2 == null;
    } else {
      return s1.equals(s2);
    }
  }

  /**
   * Returns <code>true</code> iff the ref starts with the given prefix.
   * Otherwise <code>false</code>.
   * 
   * @param ref
   *          the {@link BytesRef} to test
   * @param prefix
   *          the expected prefix
   * @return Returns <code>true</code> iff the ref starts with the given prefix.
   *         Otherwise <code>false</code>.
   */
  public static boolean startsWith(BytesRef ref, BytesRef prefix) {
    return sliceEquals(ref, prefix, 0);
  }

  private static boolean sliceEquals(BytesRef sliceToTest, BytesRef other, int pos) {
    if (pos < 0 || sliceToTest.length - pos < other.length) {
      return false;
    }
    int i = sliceToTest.offset + pos;
    int j = other.offset;
    final int k = other.offset + other.length;
    
    while (j < k) {
      if (sliceToTest.bytes[i++] != other.bytes[j++]) {
        return false;
      }
    }
    
    return true;
  }

  /** Pass this as the seed to {@link #murmurhash3_x86_32}. */

  // Poached from Guava: set a different salt/seed
  // for each JVM instance, to frustrate hash key collision
  // denial of service attacks, and to catch any places that
  // somehow rely on hash function/order across JVM
  // instances:
  public static final int GOOD_FAST_HASH_SEED;

  static {
    String prop = System.getProperty("tests.seed");
    if (prop != null) {
      // So if there is a test failure that relied on hash
      // order, we remain reproducible based on the test seed:
      GOOD_FAST_HASH_SEED = prop.hashCode();
    } else {
      GOOD_FAST_HASH_SEED = (int) System.currentTimeMillis();
    }
  }

  /** Returns the MurmurHash3_x86_32 hash.
   * Original source/tests at https://github.com/yonik/java_util/
   */
  @SuppressWarnings("fallthrough")
  public static int murmurhash3_x86_32(byte[] data, int offset, int len, int seed) {

    final int c1 = 0xcc9e2d51;
    final int c2 = 0x1b873593;

    int h1 = seed;
    int roundedEnd = offset + (len & 0xfffffffc);  // round down to 4 byte block

    for (int i=offset; i<roundedEnd; i+=4) {
      // little endian load order
      int k1 = (data[i] & 0xff) | ((data[i+1] & 0xff) << 8) | ((data[i+2] & 0xff) << 16) | (data[i+3] << 24);
      k1 *= c1;
      k1 = Integer.rotateLeft(k1, 15);
      k1 *= c2;

      h1 ^= k1;
      h1 = Integer.rotateLeft(h1, 13);
      h1 = h1*5+0xe6546b64;
    }

    // tail
    int k1 = 0;

    switch(len & 0x03) {
      case 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16;
        // fallthrough
      case 2:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8;
        // fallthrough
      case 1:
        k1 |= (data[roundedEnd] & 0xff);
        k1 *= c1;
        k1 = Integer.rotateLeft(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    }

    // finalization
    h1 ^= len;

    // fmix(h1);
    h1 ^= h1 >>> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >>> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >>> 16;

    return h1;
  }

  public static int murmurhash3_x86_32(BytesRef bytes, int seed) {
    return murmurhash3_x86_32(bytes.bytes, bytes.offset, bytes.length, seed);
  }

  static {
    // 128 bit unsigned mask
    byte[] maskBytes128 = new byte[16];
    Arrays.fill(maskBytes128, (byte) 0xff);

    String prop = System.getProperty("tests.seed");

    // State for xorshift128:
    long x0;
    long x1;

    if (prop != null) {
      // So if there is a test failure that somehow relied on this id,
      // we remain reproducible based on the test seed:
      if (prop.length() > 8) {
        prop = prop.substring(prop.length()-8);
      }
      x0 = Long.parseLong(prop, 16);
      x1 = x0;
    } else {
      // seed from /dev/urandom, if its available
      try (DataInputStream is = new DataInputStream(Files.newInputStream(Paths.get("/dev/urandom")))) {
        x0 = is.readLong();
        x1 = is.readLong();
      } catch (Exception unavailable) {
        // may not be available on this platform
        // fall back to lower quality randomness from 3 different sources:
        x0 = System.nanoTime();
        x1 = StringHelper.class.hashCode() << 32;
        
        StringBuilder sb = new StringBuilder();
        // Properties can vary across JVM instances:
        try {
          Properties p = System.getProperties();
          for (String s: p.stringPropertyNames()) {
            sb.append(s);
            sb.append(p.getProperty(s));
          }
          x1 |= sb.toString().hashCode();
        } catch (SecurityException notallowed) {
          // getting Properties requires wildcard read-write: may not be allowed
          x1 |= StringBuffer.class.hashCode();
        }
      }
    }

    // Use a few iterations of xorshift128 to scatter the seed
    // in case multiple Lucene instances starting up "near" the same
    // nanoTime, since we use ++ (mod 2^128) for full period cycle:
    for(int i=0;i<10;i++) {
      long s1 = x0;
      long s0 = x1;
      x0 = s0;
      s1 ^= s1 << 23; // a
      x1 = s1 ^ s0 ^ (s1 >>> 17) ^ (s0 >>> 26); // b, c
    }
    
    // 64-bit unsigned mask
    byte[] maskBytes64 = new byte[8];
    Arrays.fill(maskBytes64, (byte) 0xff);
  }

}
