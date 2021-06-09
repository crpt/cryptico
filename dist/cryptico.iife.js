var cryptico = (function (exports) {
  'use strict';

  /*
   *  jsaes version 0.1  -  Copyright 2006 B. Poettering
   *
   *  This program is free software; you can redistribute it and/or
   *  modify it under the terms of the GNU General Public License as
   *  published by the Free Software Foundation; either version 2 of the
   *  License, or (at your option) any later version.
   *
   *  This program is distributed in the hope that it will be useful,
   *  but WITHOUT ANY WARRANTY; without even the implied warranty of
   *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   *  General Public License for more details.
   *
   *  You should have received a copy of the GNU General Public License
   *  along with this program; if not, write to the Free Software
   *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   *  02111-1307 USA
   */
  const aes = {
      // eslint-disable-next-line prettier/prettier
      Sbox: [
          99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
          202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114,
          192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49,
          21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9,
          131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
          0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170,
          251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143,
          146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236,
          95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34,
          42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6,
          36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213,
          78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166,
          180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3,
          246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217,
          142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230,
          66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
      ],
      ShiftRowTab: [
          0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
      ],
      Sbox_Inv: new Array(256),
      ShiftRowTab_Inv: new Array(16),
      xtime: new Array(256),
      Init() {
          for (let i = 0; i < 256; i++)
              this.Sbox_Inv[this.Sbox[i]] = i;
          for (let i = 0; i < 16; i++)
              this.ShiftRowTab_Inv[this.ShiftRowTab[i]] = i;
          for (let i = 0; i < 128; i++) {
              this.xtime[i] = i << 1;
              this.xtime[128 + i] = (i << 1) ^ 0x1b;
          }
      },
      Done() {
          this.Sbox_Inv.length = 0;
          this.Sbox_Inv.length = 256;
          this.ShiftRowTab_Inv.length = 0;
          this.ShiftRowTab_Inv.length = 16;
          this.xtime.length = 0;
          this.xtime.length = 256;
      },
      ExpandKey(key) {
          const kl = key.length;
          let ks, Rcon = 1;
          switch (kl) {
              case 16:
                  ks = 16 * (10 + 1);
                  break;
              case 24:
                  ks = 16 * (12 + 1);
                  break;
              case 32:
                  ks = 16 * (14 + 1);
                  break;
              default:
                  throw 'my.ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!';
          }
          for (let i = kl; i < ks; i += 4) {
              let temp = key.slice(i - 4, i);
              if (i % kl === 0) {
                  temp = [
                      aes.Sbox[temp[1]] ^ Rcon,
                      aes.Sbox[temp[2]],
                      aes.Sbox[temp[3]],
                      aes.Sbox[temp[0]],
                  ];
                  if ((Rcon <<= 1) >= 256)
                      Rcon ^= 0x11b;
              }
              else if (kl > 24 && i % kl === 16)
                  temp = [
                      aes.Sbox[temp[0]],
                      aes.Sbox[temp[1]],
                      aes.Sbox[temp[2]],
                      aes.Sbox[temp[3]],
                  ];
              for (let j = 0; j < 4; j++)
                  key[i + j] = key[i + j - kl] ^ temp[j];
          }
      },
      Encrypt(block, key) {
          const l = key.length;
          aes.AddRoundKey(block, key.slice(0, 16));
          let i;
          for (i = 16; i < l - 16; i += 16) {
              aes.SubBytes(block, aes.Sbox);
              aes.ShiftRows(block, aes.ShiftRowTab);
              aes.MixColumns(block);
              aes.AddRoundKey(block, key.slice(i, i + 16));
          }
          aes.SubBytes(block, aes.Sbox);
          aes.ShiftRows(block, aes.ShiftRowTab);
          aes.AddRoundKey(block, key.slice(i, l));
      },
      Decrypt(block, key) {
          const l = key.length;
          aes.AddRoundKey(block, key.slice(l - 16, l));
          aes.ShiftRows(block, aes.ShiftRowTab_Inv);
          aes.SubBytes(block, aes.Sbox_Inv);
          for (let i = l - 32; i >= 16; i -= 16) {
              aes.AddRoundKey(block, key.slice(i, i + 16));
              aes.MixColumns_Inv(block);
              aes.ShiftRows(block, aes.ShiftRowTab_Inv);
              aes.SubBytes(block, aes.Sbox_Inv);
          }
          aes.AddRoundKey(block, key.slice(0, 16));
      },
      SubBytes(state, sbox) {
          for (let i = 0; i < 16; i++)
              state[i] = sbox[state[i]];
      },
      AddRoundKey(state, rkey) {
          for (let i = 0; i < 16; i++)
              state[i] ^= rkey[i];
      },
      ShiftRows(state, shifttab) {
          const h = new Array().concat(state);
          for (let i = 0; i < 16; i++)
              state[i] = h[shifttab[i]];
      },
      MixColumns(state) {
          for (let i = 0; i < 16; i += 4) {
              const s0 = state[i + 0], s1 = state[i + 1];
              const s2 = state[i + 2], s3 = state[i + 3];
              const h = s0 ^ s1 ^ s2 ^ s3;
              state[i + 0] ^= h ^ aes.xtime[s0 ^ s1];
              state[i + 1] ^= h ^ aes.xtime[s1 ^ s2];
              state[i + 2] ^= h ^ aes.xtime[s2 ^ s3];
              state[i + 3] ^= h ^ aes.xtime[s3 ^ s0];
          }
      },
      MixColumns_Inv(state) {
          for (let i = 0; i < 16; i += 4) {
              const s0 = state[i + 0], s1 = state[i + 1];
              const s2 = state[i + 2], s3 = state[i + 3];
              const h = s0 ^ s1 ^ s2 ^ s3;
              const xh = aes.xtime[h];
              const h1 = aes.xtime[aes.xtime[xh ^ s0 ^ s2]] ^ h;
              const h2 = aes.xtime[aes.xtime[xh ^ s1 ^ s3]] ^ h;
              state[i + 0] ^= h1 ^ aes.xtime[s0 ^ s1];
              state[i + 1] ^= h2 ^ aes.xtime[s1 ^ s2];
              state[i + 2] ^= h1 ^ aes.xtime[s2 ^ s3];
              state[i + 3] ^= h2 ^ aes.xtime[s3 ^ s0];
          }
      },
  };

  // seedrandom.js version 2.0.
  // Author: David Bau 4/2/2011
  //
  // Defines a method math.seedrandom() that, when called, substitutes
  // an explicitly seeded RC4-based algorithm for math.random().  Also
  // supports automatic seeding from local or network sources of entropy.
  //
  // Usage:
  //
  //   <script src=http://davidbau.com/encode/seedrandom-min.js></script>
  //
  //   Math.seedrandom('yipee'); Sets math.random to a function that is
  //                             initialized using the given explicit seed.
  //
  //   Math.seedrandom();        Sets math.random to a function that is
  //                             seeded using the current time, dom state,
  //                             and other accumulated local entropy.
  //                             The generated seed string is returned.
  //
  //   Math.seedrandom('yowza', true);
  //                             Seeds using the given explicit seed mixed
  //                             together with accumulated entropy.
  //
  //   <script src="http://bit.ly/srandom-512"></script>
  //                             Seeds using physical random bits downloaded
  //                             from random.org.
  //
  //   <script src="https://jsonlib.appspot.com/urandom?callback=Math.seedrandom">
  //   </script>                 Seeds using urandom bits from call.jsonlib.com,
  //                             which is faster than random.org.
  //
  // Examples:
  //
  //   math.seedrandom("hello");            // Use "hello" as the seed.
  //   document.write(math.random());       // Always 0.5463663768140734
  //   document.write(math.random());       // Always 0.43973793770592234
  //   let rng1 = math.random;              // Remember the current prng.
  //
  //   let autoseed = math.seedrandom();    // New prng with an automatic seed.
  //   document.write(math.random());       // Pretty much unpredictable.
  //
  //   math.random = rng1;                  // Continue "hello" prng sequence.
  //   document.write(math.random());       // Always 0.554769432473455
  //
  //   Math.seedrandom(autoseed);           // Restart at the previous seed.
  //   document.write(math.random());       // Repeat the 'unpredictable' value.
  //
  // Notes:
  //
  // Each time seedrandom('arg') is called, entropy from the passed seed
  // is accumulated in a pool to help generate future seeds for the
  // zero-argument form of Math.seedrandom, so entropy can be injected over
  // time by calling seedrandom with explicit data repeatedly.
  //
  // On speed - This javascript implementation of math.random() is about
  // 3-10x slower than the built-in Math.random() because it is not native
  // code, but this is typically fast enough anyway.  Seeding is more expensive,
  // especially if you use auto-seeding.  Some details (timings on Chrome 4):
  //
  // Our math.random()            - avg less than 0.002 milliseconds per call
  // seedrandom('explicit')       - avg less than 0.5 milliseconds per call
  // seedrandom('explicit', true) - avg less than 2 milliseconds per call
  // seedrandom()                 - avg about 38 milliseconds per call
  //
  // LICENSE (BSD):
  //
  // Copyright 2010 David Bau, all rights reserved.
  //
  // Redistribution and use in source and binary forms, with or without
  // modification, are permitted provided that the following conditions are met:
  //
  //   1. Redistributions of source code must retain the above copyright
  //      notice, this list of conditions and the following disclaimer.
  //
  //   2. Redistributions in binary form must reproduce the above copyright
  //      notice, this list of conditions and the following disclaimer in the
  //      documentation and/or other materials provided with the distribution.
  //
  //   3. Neither the name of this module nor the names of its contributors may
  //      be used to endorse or promote products derived from this software
  //      without specific prior written permission.
  //
  // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  // "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  // LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  // A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  // OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  // SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  // LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  // DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  // THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  // (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  // OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  //
  const pool = []; // pool: entropy pool starts empty
  const width = 256; // width: each RC4 output is 0 <= x < 256
  const chunks = 6; // chunks: at least six RC4 outputs for each double
  //
  // The following constants are related to IEEE 754 limits.
  //
  const significance = Math.pow(2, 52); // significance: there are 52 significant digits in a double
  const overflow = significance * 2;
  const startdenom = Math.pow(width, chunks);
  const math = {
      //
      // seedrandom()
      // This is the seedrandom function described above.
      //
      seedrandom(seed, use_entropy = false) {
          const key = [];
          // Flatten the seed string or build one from local entropy if needed.
          seed = mixkey(flatten(use_entropy
              ? [seed, pool]
              : arguments.length
                  ? seed
                  : [new Date().getTime(), pool], 3), key);
          // Use the seed to initialize an ARC4 generator.
          const arc4 = new ARC4(key);
          // Mix the randomness into accumulated entropy.
          mixkey(arc4.S, pool);
          // Override math.random
          // This function returns a random double in [0, 1) that contains
          // randomness in every bit of the mantissa of the IEEE 754 value.
          math.random = function () {
              // Closure to return a random double:
              let n = arc4.g(chunks); // Start with a numerator n < 2 ^ 48
              let d = startdenom; //   and denominator d = 2 ^ 48.
              let x = 0; //   and no 'extra last byte'.
              while (n < significance) {
                  // Fill up all significant digits by
                  n = (n + x) * width; //   shifting numerator and
                  d *= width; //   denominator and generating a
                  x = arc4.g(1); //   new least-significant-byte.
              }
              while (n >= overflow) {
                  // To avoid rounding up, before adding
                  n /= 2; //   last byte, shift everything
                  d /= 2; //   right using integer math until
                  x >>>= 1; //   we have exactly the desired bits.
              }
              return (n + x) / d; // Form the number within [0, 1).
          };
          // Return the seed that was used
          return seed;
      },
      random: function () {
          return Math.random();
      },
  };
  //
  // ARC4
  //
  // An ARC4 implementation.  The constructor takes a key in the form of
  // an array of at most (width) integers that should be 0 <= x < (width).
  //
  // The g(count) method returns a pseudorandom integer that concatenates
  // the next (count) outputs from ARC4.  Its return value is a number x
  // that is in the range 0 <= x < (width ^ count).
  //
  /** @constructor */
  class ARC4 {
      i = 0;
      j = 0;
      S = [];
      c = [];
      constructor(key) {
          let t, u, keylen = key.length;
          let i = 0, j = 0;
          // The empty key [] is treated as [0].
          if (!keylen) {
              key = [keylen++];
          }
          // Set up S using the standard key scheduling algorithm.
          while (i < width) {
              this.S[i] = i++;
          }
          for (i = 0; i < width; i++) {
              t = this.S[i];
              j = lowbits(j + t + key[i % keylen]);
              u = this.S[j];
              this.S[i] = u;
              this.S[j] = t;
          }
          // For robust unpredictability discard an initial batch of values.
          // See http://www.rsa.com/rsalabs/node.asp?id=2009
          this.g(width);
      }
      // The "g" method returns the next (count) outputs as one number.
      g(count) {
          const s = this.S;
          let i = lowbits(this.i + 1);
          let t = s[i];
          let j = lowbits(this.j + t);
          let u = s[j];
          s[i] = u;
          s[j] = t;
          let r = s[lowbits(t + u)];
          while (--count) {
              i = lowbits(i + 1);
              t = s[i];
              j = lowbits(j + t);
              u = s[j];
              s[i] = u;
              s[j] = t;
              r = r * width + s[lowbits(t + u)];
          }
          this.i = i;
          this.j = j;
          return r;
      }
  }
  //
  // flatten()
  // Converts an object tree to nested arrays of strings.
  //
  /** @param {Object=} result
   * @param {string=} prop
   * @param {string=} typ */
  function flatten(obj, depth) {
      const result = [];
      const typ = typeof obj;
      if (depth && typ === 'object') {
          for (const prop in obj) {
              if (prop.indexOf('S') < 5) {
                  // Avoid FF3 bug (local/sessionStorage)
                  try {
                      result.push(flatten(obj[prop], depth - 1));
                  }
                  catch (e) {
                      console.error(e);
                  }
              }
          }
      }
      return result.length ? result : obj + (typ !== 'string' ? '\0' : '');
  }
  //
  // mixkey()
  // Mixes a string seed into a key that is an array of integers, and
  // returns a shortened string seed that is equivalent to the result key.
  //
  /** @param {number=} smear
   * @param {number=} j */
  function mixkey(seed, key) {
      const seedStr = seed + ''; // Ensure the seed is a string
      let smear = 0;
      for (let i = 0; i < seedStr.length; i++) {
          key[lowbits(i)] = lowbits((smear ^= key[lowbits(i)] * 19) + seedStr.charCodeAt(i));
      }
      let mixed = '';
      key.forEach((v) => (mixed += String.fromCharCode(v)));
      return mixed;
  }
  //
  // lowbits()
  // A quick "n mod width" for width a power of 2.
  //
  function lowbits(n) {
      return n & (width - 1);
  }
  //
  // When seedrandom.js is loaded, we immediately mix a few bits
  // from the built-in RNG into the entropy pool.  Because we do
  // not want to intefere with determinstic PRNG state later,
  // seedrandom will not call math.random on its own again after
  // initialization.
  //
  mixkey(Math.random(), pool);
  // This is not really a random number generator object, and two SeededRandom
  // objects will conflict with one another, but it's good enough for generating
  // the rsa key.
  class SeededRandom {
      nextBytes(ba) {
          for (let i = 0; i < ba.length; i++) {
              ba[i] = Math.floor(math.random() * 256);
          }
      }
  }
  // prng4.js - uses Arcfour as a PRNG
  class Arcfour {
      i = 0;
      j = 0;
      S = [];
      // Initialize arcfour context from key, an array of ints, each from [0..255]
      init(key) {
          let i, j, t;
          for (i = 0; i < 256; ++i)
              this.S[i] = i;
          j = 0;
          for (i = 0; i < 256; ++i) {
              j = (j + this.S[i] + key[i % key.length]) & 255;
              t = this.S[i];
              this.S[i] = this.S[j];
              this.S[j] = t;
          }
          this.i = 0;
          this.j = 0;
      }
      next() {
          this.i = (this.i + 1) & 255;
          this.j = (this.j + this.S[this.i]) & 255;
          const t = this.S[this.i];
          this.S[this.i] = this.S[this.j];
          this.S[this.j] = t;
          return this.S[(t + this.S[this.i]) & 255];
      }
  }
  // Plug in your RNG constructor here
  function prng_newstate() {
      return new Arcfour();
  }
  // Pool size must be a multiple of 4 and greater than 32.
  // An array of bytes the size of the pool will be passed to init()
  const rng_psize = 256;
  // Random number generator - requires a PRNG backend, e.g. prng4.js
  // For best results, put code like
  // <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
  // in your main HTML document.
  let rng_state;
  let rng_pool = [];
  let rng_pptr;
  // Mix in a 32-bit integer into the pool
  function rng_seed_int(x) {
      rng_pool[rng_pptr++] ^= x & 255;
      rng_pool[rng_pptr++] ^= (x >> 8) & 255;
      rng_pool[rng_pptr++] ^= (x >> 16) & 255;
      rng_pool[rng_pptr++] ^= (x >> 24) & 255;
      if (rng_pptr >= rng_psize)
          rng_pptr -= rng_psize;
  }
  // Mix in the current time (w/milliseconds) into the pool
  function rng_seed_time() {
      rng_seed_int(new Date().getTime());
  }
  // Initialize the pool with junk if needed.
  if (!rng_pool) {
      rng_pool = [];
      rng_pptr = 0;
      let t;
      while (rng_pptr < rng_psize) {
          // extract some randomness from Math.random()
          t = Math.floor(65536 * Math.random());
          rng_pool[rng_pptr++] = t >>> 8;
          rng_pool[rng_pptr++] = t & 255;
      }
      rng_pptr = 0;
      rng_seed_time();
      //rng_seed_int(window.screenX);
      //rng_seed_int(window.screenY);
  }
  function rng_get_byte() {
      if (!rng_state) {
          rng_seed_time();
          rng_state = prng_newstate();
          rng_state.init(rng_pool);
          for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
              rng_pool[rng_pptr] = 0;
          rng_pptr = 0;
          //rng_pool = null;
      }
      // TODO: allow reseeding after first request
      return rng_state.next();
  }
  class SecureRandom {
      nextBytes(ba) {
          let i;
          for (i = 0; i < ba.length; ++i)
              ba[i] = rng_get_byte();
      }
  }

  // Copyright (c) 2005  Tom Wu
  const op_and = (x, y) => x & y;
  const op_or = (x, y) => x | y;
  const op_xor = (x, y) => x ^ y;
  const op_andnot = (x, y) => x & ~y;
  const dbits = 30;
  const BI_FP = 52;
  class BigInteger {
      static DB = dbits;
      static DM = (1 << dbits) - 1;
      static DV = 1 << dbits;
      static FV = Math.pow(2, BI_FP);
      static F1 = BI_FP - dbits;
      static F2 = 2 * dbits - BI_FP;
      // "constants"
      static ZERO = new BigInteger(0);
      static ONE = new BigInteger(1);
      // FIXME: ;
      s = 0;
      t = 0;
      constructor(a, b, c) {
          if (a) {
              if ('number' === typeof a) {
                  if (b) {
                      this.fromNumber(a, b, c);
                  }
                  else {
                      // return bigint initialized to value
                      this.fromInt(a);
                  }
              }
              else {
                  this.fromString(a, b || 256);
              }
          }
      }
      // am avoids a big mult-and-extract completely.
      // Max digit bits should be <= 30 because we do bitwise ops
      // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
      am(i, x, w, j, c, n) {
          const xl = x & 0x7fff, xh = x >> 15;
          while (--n >= 0) {
              let l = this[i] & 0x7fff;
              const h = this[i++] >> 15;
              const m = xh * l + h * xl;
              l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
              c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
              w[j++] = l & 0x3fffffff;
          }
          return c;
      }
      // copy this to r
      copyTo(r) {
          for (let i = this.t - 1; i >= 0; --i)
              r[i] = this[i];
          r.t = this.t;
          r.s = this.s;
      }
      // set from integer value x, -DV <= x < DV
      fromInt(x) {
          this.t = 1;
          this.s = x < 0 ? -1 : 0;
          if (x > 0)
              this[0] = x;
          else if (x < -1)
              this[0] = x + BigInteger.DV;
          else
              this.t = 0;
      }
      // set from string and radix
      fromString(s, b) {
          let k;
          if (b === 16)
              k = 4;
          else if (b === 8)
              k = 3;
          else if (b === 256)
              k = 8;
          // byte array
          else if (b === 2)
              k = 1;
          else if (b === 32)
              k = 5;
          else if (b === 4)
              k = 2;
          else {
              this.fromRadix(s, b);
              return;
          }
          this.t = 0;
          this.s = 0;
          let i = s.length, mi = false, sh = 0;
          while (--i >= 0) {
              const x = k === 8 ? s[i] : intAt(s, i);
              if (x < 0) {
                  if (s.charAt(i) === '-')
                      mi = true;
                  continue;
              }
              mi = false;
              if (sh === 0)
                  this[this.t++] = x;
              else if (sh + k > BigInteger.DB) {
                  this[this.t - 1] |= (x & ((1 << (BigInteger.DB - sh)) - 1)) << sh;
                  this[this.t++] = x >> (BigInteger.DB - sh);
              }
              else
                  this[this.t - 1] |= x << sh;
              sh += k;
              if (sh >= BigInteger.DB)
                  sh -= BigInteger.DB;
          }
          if (k === 8 && (s[0] & 0x80) !== 0) {
              this.s = -1;
              if (sh > 0)
                  this[this.t - 1] |= ((1 << (BigInteger.DB - sh)) - 1) << sh;
          }
          this.clamp();
          if (mi)
              BigInteger.ZERO.subTo(this, this);
      }
      // clamp off excess high words
      clamp() {
          const c = this.s & BigInteger.DM;
          while (this.t > 0 && this[this.t - 1] === c)
              --this.t;
      }
      // return string representation in given radix (default to 16)
      toString(b = 16) {
          if (this.s < 0)
              return '-' + this.negate().toString(b);
          let k;
          if (b === 16)
              k = 4;
          else if (b === 8)
              k = 3;
          else if (b === 2)
              k = 1;
          else if (b === 32)
              k = 5;
          else if (b === 64)
              k = 6;
          else if (b === 4)
              k = 2;
          else
              return this.toRadix(b);
          const km = (1 << k) - 1;
          let d, m = false, r = '', i = this.t;
          let p = BigInteger.DB - ((i * BigInteger.DB) % k);
          if (i-- > 0) {
              if (p < BigInteger.DB && (d = this[i] >> p) > 0) {
                  m = true;
                  r = int2char(d);
              }
              while (i >= 0) {
                  if (p < k) {
                      d = (this[i] & ((1 << p) - 1)) << (k - p);
                      d |= this[--i] >> (p += BigInteger.DB - k);
                  }
                  else {
                      d = (this[i] >> (p -= k)) & km;
                      if (p <= 0) {
                          p += BigInteger.DB;
                          --i;
                      }
                  }
                  if (d > 0)
                      m = true;
                  if (m)
                      r += int2char(d);
              }
          }
          return m ? r : '0';
      }
      // -this
      negate() {
          const r = new BigInteger();
          BigInteger.ZERO.subTo(this, r);
          return r;
      }
      // |this|
      abs() {
          return this.s < 0 ? this.negate() : this;
      }
      // return + if this > a, - if this < a, 0 if equal
      compareTo(a) {
          let r = this.s - a.s;
          if (r !== 0)
              return r;
          let i = this.t;
          r = i - a.t;
          if (r !== 0)
              return r;
          while (--i >= 0)
              if ((r = this[i] - a[i]) !== 0)
                  return r;
          return 0;
      }
      // return the number of bits in "this"
      bitLength() {
          if (this.t <= 0)
              return 0;
          return (BigInteger.DB * (this.t - 1) +
              nbits(this[this.t - 1] ^ (this.s & BigInteger.DM)));
      }
      // r = this << n*DB
      dlShiftTo(n, r) {
          let i;
          for (i = this.t - 1; i >= 0; --i)
              r[i + n] = this[i];
          for (i = n - 1; i >= 0; --i)
              r[i] = 0;
          r.t = this.t + n;
          r.s = this.s;
      }
      // r = this >> n*DB
      drShiftTo(n, r) {
          for (let i = n; i < this.t; ++i)
              r[i - n] = this[i];
          r.t = Math.max(this.t - n, 0);
          r.s = this.s;
      }
      // r = this << n
      lShiftTo(n, r) {
          const bs = n % BigInteger.DB;
          const cbs = BigInteger.DB - bs;
          const bm = (1 << cbs) - 1;
          const ds = Math.floor(n / BigInteger.DB);
          let c = (this.s << bs) & BigInteger.DM, i;
          for (i = this.t - 1; i >= 0; --i) {
              r[i + ds + 1] = (this[i] >> cbs) | c;
              c = (this[i] & bm) << bs;
          }
          for (i = ds - 1; i >= 0; --i)
              r[i] = 0;
          r[ds] = c;
          r.t = this.t + ds + 1;
          r.s = this.s;
          r.clamp();
      }
      // r = this >> n
      rShiftTo(n, r) {
          r.s = this.s;
          const ds = Math.floor(n / BigInteger.DB);
          if (ds >= this.t) {
              r.t = 0;
              return;
          }
          const bs = n % BigInteger.DB;
          const cbs = BigInteger.DB - bs;
          const bm = (1 << bs) - 1;
          r[0] = this[ds] >> bs;
          for (let i = ds + 1; i < this.t; ++i) {
              r[i - ds - 1] |= (this[i] & bm) << cbs;
              r[i - ds] = this[i] >> bs;
          }
          if (bs > 0)
              r[this.t - ds - 1] |= (this.s & bm) << cbs;
          r.t = this.t - ds;
          r.clamp();
      }
      // r = this - a
      subTo(a, r) {
          const m = Math.min(a.t, this.t);
          let i = 0, c = 0;
          while (i < m) {
              c += this[i] - a[i];
              r[i++] = c & BigInteger.DM;
              c >>= BigInteger.DB;
          }
          if (a.t < this.t) {
              c -= a.s;
              while (i < this.t) {
                  c += this[i];
                  r[i++] = c & BigInteger.DM;
                  c >>= BigInteger.DB;
              }
              c += this.s;
          }
          else {
              c += this.s;
              while (i < a.t) {
                  c -= a[i];
                  r[i++] = c & BigInteger.DM;
                  c >>= BigInteger.DB;
              }
              c -= a.s;
          }
          r.s = c < 0 ? -1 : 0;
          if (c < -1)
              r[i++] = BigInteger.DV + c;
          else if (c > 0)
              r[i++] = c;
          r.t = i;
          r.clamp();
      }
      // r = this * a, r !== this,a (HAC 14.12)
      // "this" should be the larger one if appropriate.
      multiplyTo(a, r) {
          const x = this.abs(), y = a.abs();
          let i = x.t;
          r.t = i + y.t;
          while (--i >= 0)
              r[i] = 0;
          for (i = 0; i < y.t; ++i)
              r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
          r.s = 0;
          r.clamp();
          if (this.s !== a.s)
              BigInteger.ZERO.subTo(r, r);
      }
      // r = this^2, r !== this (HAC 14.16)
      squareTo(r) {
          const x = this.abs();
          let i = (r.t = 2 * x.t);
          while (--i >= 0)
              r[i] = 0;
          for (i = 0; i < x.t - 1; ++i) {
              const c = x.am(i, x[i], r, 2 * i, 0, 1);
              if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >=
                  BigInteger.DV) {
                  r[i + x.t] -= BigInteger.DV;
                  r[i + x.t + 1] = 1;
              }
          }
          if (r.t > 0)
              r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
          r.s = 0;
          r.clamp();
      }
      // divide this by m, quotient and remainder to q, r (HAC 14.20)
      // r !== q, this !== m.  q or r may be null.
      divRemTo(m, q, r) {
          const pm = m.abs();
          if (pm.t <= 0)
              return;
          const pt = this.abs();
          if (pt.t < pm.t) {
              if (q)
                  q.fromInt(0);
              if (r)
                  this.copyTo(r);
              return;
          }
          if (!r)
              r = new BigInteger();
          const y = new BigInteger(), ts = this.s, ms = m.s;
          const nsh = BigInteger.DB - nbits(pm[pm.t - 1]); // normalize modulus
          if (nsh > 0) {
              pm.lShiftTo(nsh, y);
              pt.lShiftTo(nsh, r);
          }
          else {
              pm.copyTo(y);
              pt.copyTo(r);
          }
          const ys = y.t;
          const y0 = y[ys - 1];
          if (y0 === 0)
              return;
          const yt = y0 * (1 << BigInteger.F1) + (ys > 1 ? y[ys - 2] >> BigInteger.F2 : 0);
          const d1 = BigInteger.FV / yt, d2 = (1 << BigInteger.F1) / yt, e = 1 << BigInteger.F2, t = q || new BigInteger();
          let i = r.t, j = i - ys;
          y.dlShiftTo(j, t);
          if (r.compareTo(t) >= 0) {
              r[r.t++] = 1;
              r.subTo(t, r);
          }
          BigInteger.ONE.dlShiftTo(ys, t);
          t.subTo(y, y); // "negative" y so we can replace sub with am later
          while (y.t < ys)
              y[y.t++] = 0;
          while (--j >= 0) {
              // Estimate quotient digit
              let qd = r[--i] === y0
                  ? BigInteger.DM
                  : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
              if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
                  // Try it out
                  y.dlShiftTo(j, t);
                  r.subTo(t, r);
                  while (r[i] < --qd)
                      r.subTo(t, r);
              }
          }
          if (q) {
              r.drShiftTo(ys, q);
              if (ts !== ms)
                  BigInteger.ZERO.subTo(q, q);
          }
          r.t = ys;
          r.clamp();
          if (nsh > 0)
              r.rShiftTo(nsh, r); // Denormalize remainder
          if (ts < 0)
              BigInteger.ZERO.subTo(r, r);
      }
      // this mod a
      mod(a) {
          const r = new BigInteger();
          this.abs().divRemTo(a, undefined, r);
          if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
              a.subTo(r, r);
          return r;
      }
      // return "-1/this % 2^DB"; useful for Mont. reduction
      // justification:
      //         xy === 1 (mod m)
      //         xy =  1+km
      //   xy(2-xy) = (1+km)(1-km)
      // x[y(2-xy)] = 1-k^2m^2
      // x[y(2-xy)] === 1 (mod m^2)
      // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
      // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
      // JS multiply "overflows" differently from C/C++, so care is needed here.
      invDigit() {
          if (this.t < 1)
              return 0;
          const x = this[0];
          if ((x & 1) === 0)
              return 0;
          let y = x & 3; // y === 1/x mod 2^2
          y = (y * (2 - (x & 0xf) * y)) & 0xf; // y === 1/x mod 2^4
          y = (y * (2 - (x & 0xff) * y)) & 0xff; // y === 1/x mod 2^8
          y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y === 1/x mod 2^16
          // last step - calculate inverse mod DV directly;
          // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
          y = (y * (2 - ((x * y) % BigInteger.DV))) % BigInteger.DV; // y === 1/x mod 2^dbits
          // we really want the negative inverse, and -DV < y < DV
          return y > 0 ? BigInteger.DV - y : -y;
      }
      // true iff this is even
      isEven() {
          return (this.t > 0 ? this[0] & 1 : this.s) === 0;
      }
      // this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
      exp(e, z) {
          if (e > 0xffffffff || e < 1)
              return BigInteger.ONE;
          const g = z.convert(this);
          let r = new BigInteger(), r2 = new BigInteger(), i = nbits(e) - 1;
          g.copyTo(r);
          while (--i >= 0) {
              z.sqrTo(r, r2);
              if ((e & (1 << i)) > 0)
                  z.mulTo(r2, g, r);
              else {
                  const t = r;
                  r = r2;
                  r2 = t;
              }
          }
          return z.revert(r);
      }
      // this^e % m, 0 <= e < 2^32
      modPowInt(e, m) {
          let z;
          if (e < 256 || m.isEven())
              z = new Classic(m);
          else
              z = new Montgomery(m);
          return this.exp(e, z);
      }
      clone() {
          const r = new BigInteger();
          this.copyTo(r);
          return r;
      }
      // return value as integer
      intValue() {
          if (this.s < 0) {
              if (this.t === 1)
                  return this[0] - BigInteger.DV;
              else if (this.t === 0)
                  return -1;
          }
          else if (this.t === 1)
              return this[0];
          else if (this.t === 0)
              return 0;
          // assumes 16 < DB < 32
          return (((this[1] & ((1 << (32 - BigInteger.DB)) - 1)) << BigInteger.DB) | this[0]);
      }
      // return value as byte
      byteValue() {
          return this.t === 0 ? this.s : (this[0] << 24) >> 24;
      }
      // return value as short (assumes DB>=16)
      shortValue() {
          return this.t === 0 ? this.s : (this[0] << 16) >> 16;
      }
      // return x s.t. r^x < DV
      chunkSize(r) {
          return Math.floor((Math.LN2 * BigInteger.DB) / Math.log(r));
      }
      // 0 if this === 0, 1 if this > 0, -1 if this < 0
      signum() {
          if (this.s < 0)
              return -1;
          else if (this.t <= 0 || (this.t === 1 && this[0] <= 0))
              return 0;
          else
              return 1;
      }
      // convert to radix string
      toRadix(b) {
          if (!b)
              b = 10;
          if (this.signum() === 0 || b < 2 || b > 36)
              return '0';
          const cs = this.chunkSize(b);
          const a = Math.pow(b, cs);
          const d = new BigInteger(a), y = new BigInteger(), z = new BigInteger();
          let r = '';
          this.divRemTo(d, y, z);
          while (y.signum() > 0) {
              r = (a + z.intValue()).toString(b).substr(1) + r;
              y.divRemTo(d, y, z);
          }
          return z.intValue().toString(b) + r;
      }
      // convert from radix string
      fromRadix(s, b) {
          this.fromInt(0);
          if (!b)
              b = 10;
          const cs = this.chunkSize(b);
          const d = Math.pow(b, cs);
          let mi = false, j = 0, w = 0;
          for (let i = 0; i < s.length; ++i) {
              const x = intAt(s, i);
              if (x < 0) {
                  if (s.charAt(i) === '-' && this.signum() === 0)
                      mi = true;
                  continue;
              }
              w = b * w + x;
              if (++j >= cs) {
                  this.dMultiply(d);
                  this.dAddOffset(w, 0);
                  j = 0;
                  w = 0;
              }
          }
          if (j > 0) {
              this.dMultiply(Math.pow(b, j));
              this.dAddOffset(w, 0);
          }
          if (mi)
              BigInteger.ZERO.subTo(this, this);
      }
      // alternate constructor
      fromNumber(a, b, c) {
          if ('number' === typeof b) {
              // new BigInteger(int,int,RNG)
              if (a < 2)
                  this.fromInt(1);
              else {
                  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                  this.fromNumber(a, c);
                  if (!this.testBit(a - 1))
                      // force MSB set
                      this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                  if (this.isEven())
                      this.dAddOffset(1, 0); // force odd
                  while (!this.isProbablePrime(b)) {
                      this.dAddOffset(2, 0);
                      if (this.bitLength() > a)
                          this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
                  }
              }
          }
          else {
              // new BigInteger(int,RNG)
              const x = [], t = a & 7;
              x.length = (a >> 3) + 1;
              b.nextBytes(x);
              if (t > 0)
                  x[0] &= (1 << t) - 1;
              else
                  x[0] = 0;
              this.fromString(x, 256);
          }
      }
      // convert to bigendian byte array
      toByteArray() {
          const r = [];
          let i = this.t;
          r[0] = this.s;
          let p = BigInteger.DB - ((i * BigInteger.DB) % 8), d, k = 0;
          if (i-- > 0) {
              if (p < BigInteger.DB &&
                  (d = this[i] >> p) !== (this.s & BigInteger.DM) >> p)
                  r[k++] = d | (this.s << (BigInteger.DB - p));
              while (i >= 0) {
                  if (p < 8) {
                      d = (this[i] & ((1 << p) - 1)) << (8 - p);
                      d |= this[--i] >> (p += BigInteger.DB - 8);
                  }
                  else {
                      d = (this[i] >> (p -= 8)) & 0xff;
                      if (p <= 0) {
                          p += BigInteger.DB;
                          --i;
                      }
                  }
                  if ((d & 0x80) !== 0)
                      d |= -256;
                  if (k === 0 && (this.s & 0x80) !== (d & 0x80))
                      ++k;
                  if (k > 0 || d !== this.s)
                      r[k++] = d;
              }
          }
          return r;
      }
      equals(a) {
          return this.compareTo(a) === 0;
      }
      min(a) {
          return this.compareTo(a) < 0 ? this : a;
      }
      max(a) {
          return this.compareTo(a) > 0 ? this : a;
      }
      // r = this op a (bitwise)
      bitwiseTo(a, op, r) {
          const m = Math.min(a.t, this.t);
          let f;
          for (let i = 0; i < m; ++i)
              r[i] = op(this[i], a[i]);
          if (a.t < this.t) {
              f = a.s & BigInteger.DM;
              for (let i = m; i < this.t; ++i)
                  r[i] = op(this[i], f);
              r.t = this.t;
          }
          else {
              f = this.s & BigInteger.DM;
              for (let i = m; i < a.t; ++i)
                  r[i] = op(f, a[i]);
              r.t = a.t;
          }
          r.s = op(this.s, a.s);
          r.clamp();
      }
      // this & a
      and(a) {
          const r = new BigInteger();
          this.bitwiseTo(a, op_and, r);
          return r;
      }
      // this | a
      or(a) {
          const r = new BigInteger();
          this.bitwiseTo(a, op_or, r);
          return r;
      }
      // this ^ a
      xor(a) {
          const r = new BigInteger();
          this.bitwiseTo(a, op_xor, r);
          return r;
      }
      // this & ~a
      andNot(a) {
          const r = new BigInteger();
          this.bitwiseTo(a, op_andnot, r);
          return r;
      }
      // ~this
      not() {
          const r = new BigInteger();
          for (let i = 0; i < this.t; ++i)
              r[i] = BigInteger.DM & ~this[i];
          r.t = this.t;
          r.s = ~this.s;
          return r;
      }
      // this << n
      shiftLeft(n) {
          const r = new BigInteger();
          if (n < 0)
              this.rShiftTo(-n, r);
          else
              this.lShiftTo(n, r);
          return r;
      }
      // this >> n
      shiftRight(n) {
          const r = new BigInteger();
          if (n < 0)
              this.lShiftTo(-n, r);
          else
              this.rShiftTo(n, r);
          return r;
      }
      // returns index of lowest 1-bit (or -1 if none)
      getLowestSetBit() {
          for (let i = 0; i < this.t; ++i)
              if (this[i] !== 0)
                  return i * BigInteger.DB + lbit(this[i]);
          if (this.s < 0)
              return this.t * BigInteger.DB;
          return -1;
      }
      // return number of set bits
      bitCount() {
          const x = this.s & BigInteger.DM;
          let r = 0;
          for (let i = 0; i < this.t; ++i)
              r += cbit(this[i] ^ x);
          return r;
      }
      // true iff nth bit is set
      testBit(n) {
          const j = Math.floor(n / BigInteger.DB);
          if (j >= this.t)
              return this.s !== 0;
          return (this[j] & (1 << n % BigInteger.DB)) !== 0;
      }
      // this op (1<<n)
      changeBit(n, op) {
          const r = BigInteger.ONE.shiftLeft(n);
          this.bitwiseTo(r, op, r);
          return r;
      }
      // this | (1<<n)
      setBit(n) {
          return this.changeBit(n, op_or);
      }
      // this & ~(1<<n)
      clearBit(n) {
          return this.changeBit(n, op_andnot);
      }
      // this ^ (1<<n)
      flipBit(n) {
          return this.changeBit(n, op_xor);
      }
      // r = this + a
      addTo(a, r) {
          const m = Math.min(a.t, this.t);
          let i = 0, c = 0;
          while (i < m) {
              c += this[i] + a[i];
              r[i++] = c & BigInteger.DM;
              c >>= BigInteger.DB;
          }
          if (a.t < this.t) {
              c += a.s;
              while (i < this.t) {
                  c += this[i];
                  r[i++] = c & BigInteger.DM;
                  c >>= BigInteger.DB;
              }
              c += this.s;
          }
          else {
              c += this.s;
              while (i < a.t) {
                  c += a[i];
                  r[i++] = c & BigInteger.DM;
                  c >>= BigInteger.DB;
              }
              c += a.s;
          }
          r.s = c < 0 ? -1 : 0;
          if (c > 0)
              r[i++] = c;
          else if (c < -1)
              r[i++] = BigInteger.DV + c;
          r.t = i;
          r.clamp();
      }
      // this + a
      add(a) {
          const r = new BigInteger();
          this.addTo(a, r);
          return r;
      }
      // this - a
      subtract(a) {
          const r = new BigInteger();
          this.subTo(a, r);
          return r;
      }
      // this * a
      multiply(a) {
          const r = new BigInteger();
          this.multiplyTo(a, r);
          return r;
      }
      // JSBN-specific extension
      // this^2
      square() {
          const r = new BigInteger();
          this.squareTo(r);
          return r;
      }
      // this / a
      divide(a) {
          const r = new BigInteger();
          this.divRemTo(a, r, undefined);
          return r;
      }
      // this % a
      remainder(a) {
          const r = new BigInteger();
          this.divRemTo(a, undefined, r);
          return r;
      }
      // [this/a,this%a]
      divideAndRemainder(a) {
          const q = new BigInteger(), r = new BigInteger();
          this.divRemTo(a, q, r);
          return [q, r];
      }
      // this *= n, this >= 0, 1 < n < DV
      dMultiply(n) {
          this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
          ++this.t;
          this.clamp();
      }
      // this += n << w words, this >= 0
      dAddOffset(n, w) {
          if (n === 0)
              return;
          while (this.t <= w)
              this[this.t++] = 0;
          this[w] += n;
          while (this[w] >= BigInteger.DV) {
              this[w] -= BigInteger.DV;
              if (++w >= this.t)
                  this[this.t++] = 0;
              ++this[w];
          }
      }
      // this^e
      pow(e) {
          return this.exp(e, new NullExp());
      }
      // r = lower n words of "this * a", a.t <= n
      // "this" should be the larger one if appropriate.
      multiplyLowerTo(a, n, r) {
          let i = Math.min(this.t + a.t, n);
          r.s = 0; // assumes a,this >= 0
          r.t = i;
          while (i > 0)
              r[--i] = 0;
          let j;
          for (j = r.t - this.t; i < j; ++i)
              r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
          for (j = Math.min(a.t, n); i < j; ++i)
              this.am(0, a[i], r, i, 0, n - i);
          r.clamp();
      }
      // r = "this * a" without lower n words, n > 0
      // "this" should be the larger one if appropriate.
      multiplyUpperTo(a, n, r) {
          --n;
          let i = (r.t = this.t + a.t - n);
          r.s = 0; // assumes a,this >= 0
          while (--i >= 0)
              r[i] = 0;
          for (i = Math.max(n - this.t, 0); i < a.t; ++i)
              r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
          r.clamp();
          r.drShiftTo(1, r);
      }
      // this^e % m (HAC 14.85)
      modPow(e, m) {
          let i = e.bitLength(), k, r = new BigInteger(1), z;
          if (i <= 0)
              return r;
          else if (i < 18)
              k = 1;
          else if (i < 48)
              k = 3;
          else if (i < 144)
              k = 4;
          else if (i < 768)
              k = 5;
          else
              k = 6;
          if (i < 8)
              z = new Classic(m);
          else if (m.isEven())
              z = new Barrett(m);
          else
              z = new Montgomery(m);
          // precomputation
          const g = [], k1 = k - 1, km = (1 << k) - 1;
          let n = 3;
          g[1] = z.convert(this);
          if (k > 1) {
              const g2 = new BigInteger();
              z.sqrTo(g[1], g2);
              while (n <= km) {
                  g[n] = new BigInteger();
                  z.mulTo(g2, g[n - 2], g[n]);
                  n += 2;
              }
          }
          let j = e.t - 1, w, is1 = true, r2 = new BigInteger(), t;
          i = nbits(e[j]) - 1;
          while (j >= 0) {
              if (i >= k1)
                  w = (e[j] >> (i - k1)) & km;
              else {
                  w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                  if (j > 0)
                      w |= e[j - 1] >> (BigInteger.DB + i - k1);
              }
              n = k;
              while ((w & 1) === 0) {
                  w >>= 1;
                  --n;
              }
              if ((i -= n) < 0) {
                  i += BigInteger.DB;
                  --j;
              }
              if (is1) {
                  // ret === 1, don't bother squaring or multiplying it
                  g[w].copyTo(r);
                  is1 = false;
              }
              else {
                  while (n > 1) {
                      z.sqrTo(r, r2);
                      z.sqrTo(r2, r);
                      n -= 2;
                  }
                  if (n > 0)
                      z.sqrTo(r, r2);
                  else {
                      t = r;
                      r = r2;
                      r2 = t;
                  }
                  z.mulTo(r2, g[w], r);
              }
              while (j >= 0 && (e[j] & (1 << i)) === 0) {
                  z.sqrTo(r, r2);
                  t = r;
                  r = r2;
                  r2 = t;
                  if (--i < 0) {
                      i = BigInteger.DB - 1;
                      --j;
                  }
              }
          }
          return z.revert(r);
      }
      // gcd(this,a) (HAC 14.54)
      gcd(a) {
          let x = this.s < 0 ? this.negate() : this.clone();
          let y = a.s < 0 ? a.negate() : a.clone();
          if (x.compareTo(y) < 0) {
              const t = x;
              x = y;
              y = t;
          }
          let i = x.getLowestSetBit(), g = y.getLowestSetBit();
          if (g < 0)
              return x;
          if (i < g)
              g = i;
          if (g > 0) {
              x.rShiftTo(g, x);
              y.rShiftTo(g, y);
          }
          while (x.signum() > 0) {
              if ((i = x.getLowestSetBit()) > 0)
                  x.rShiftTo(i, x);
              if ((i = y.getLowestSetBit()) > 0)
                  y.rShiftTo(i, y);
              if (x.compareTo(y) >= 0) {
                  x.subTo(y, x);
                  x.rShiftTo(1, x);
              }
              else {
                  y.subTo(x, y);
                  y.rShiftTo(1, y);
              }
          }
          if (g > 0)
              y.lShiftTo(g, y);
          return y;
      }
      // this % n, n < 2^26
      modInt(n) {
          if (n <= 0)
              return 0;
          const d = BigInteger.DV % n;
          let r = this.s < 0 ? n - 1 : 0;
          if (this.t > 0)
              if (d === 0)
                  r = this[0] % n;
              else
                  for (let i = this.t - 1; i >= 0; --i)
                      r = (d * r + this[i]) % n;
          return r;
      }
      // 1/this % m (HAC 14.61)
      modInverse(m) {
          const ac = m.isEven();
          if ((this.isEven() && ac) || m.signum() === 0)
              return BigInteger.ZERO;
          const u = m.clone(), v = this.clone();
          const a = new BigInteger(1), b = new BigInteger(0), c = new BigInteger(0), d = new BigInteger(1);
          while (u.signum() !== 0) {
              while (u.isEven()) {
                  u.rShiftTo(1, u);
                  if (ac) {
                      if (!a.isEven() || !b.isEven()) {
                          a.addTo(this, a);
                          b.subTo(m, b);
                      }
                      a.rShiftTo(1, a);
                  }
                  else if (!b.isEven())
                      b.subTo(m, b);
                  b.rShiftTo(1, b);
              }
              while (v.isEven()) {
                  v.rShiftTo(1, v);
                  if (ac) {
                      if (!c.isEven() || !d.isEven()) {
                          c.addTo(this, c);
                          d.subTo(m, d);
                      }
                      c.rShiftTo(1, c);
                  }
                  else if (!d.isEven())
                      d.subTo(m, d);
                  d.rShiftTo(1, d);
              }
              if (u.compareTo(v) >= 0) {
                  u.subTo(v, u);
                  if (ac)
                      a.subTo(c, a);
                  b.subTo(d, b);
              }
              else {
                  v.subTo(u, v);
                  if (ac)
                      c.subTo(a, c);
                  d.subTo(b, d);
              }
          }
          if (v.compareTo(BigInteger.ONE) !== 0)
              return BigInteger.ZERO;
          if (d.compareTo(m) >= 0)
              return d.subtract(m);
          if (d.signum() < 0)
              d.addTo(m, d);
          else
              return d;
          if (d.signum() < 0)
              return d.add(m);
          else
              return d;
      }
      static lowprimes = [
          2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
          73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
          157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
          239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
          331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
          421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
          509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
          613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
          709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
          821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
          919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
      ];
      static lplim = (1 << 26) / BigInteger.lowprimes[BigInteger.lowprimes.length - 1];
      // test primality with certainty >= 1-.5^t
      isProbablePrime(t) {
          const x = this.abs();
          let i;
          if (x.t === 1 &&
              x[0] <= BigInteger.lowprimes[BigInteger.lowprimes.length - 1]) {
              for (i = 0; i < BigInteger.lowprimes.length; ++i)
                  if (x[0] === BigInteger.lowprimes[i])
                      return true;
              return false;
          }
          if (x.isEven())
              return false;
          i = 1;
          while (i < BigInteger.lowprimes.length) {
              let m = BigInteger.lowprimes[i], j = i + 1;
              while (j < BigInteger.lowprimes.length && m < BigInteger.lplim)
                  m *= BigInteger.lowprimes[j++];
              m = x.modInt(m);
              while (i < j)
                  if (m % BigInteger.lowprimes[i++] === 0)
                      return false;
          }
          return x.millerRabin(t);
      }
      // true if probably prime (HAC 4.24, Miller-Rabin)
      millerRabin(t) {
          const n1 = this.subtract(BigInteger.ONE);
          const k = n1.getLowestSetBit();
          if (k <= 0)
              return false;
          const r = n1.shiftRight(k);
          t = (t + 1) >> 1;
          if (t > BigInteger.lowprimes.length)
              t = BigInteger.lowprimes.length;
          const a = new BigInteger();
          for (let i = 0; i < t; ++i) {
              //Pick bases at random, instead of starting at 2
              a.fromInt(BigInteger.lowprimes[Math.floor(math.random() * BigInteger.lowprimes.length)]);
              let y = a.modPow(r, this);
              if (y.compareTo(BigInteger.ONE) !== 0 && y.compareTo(n1) !== 0) {
                  let j = 1;
                  while (j++ < k && y.compareTo(n1) !== 0) {
                      y = y.modPowInt(2, this);
                      if (y.compareTo(BigInteger.ONE) === 0)
                          return false;
                  }
                  if (y.compareTo(n1) !== 0)
                      return false;
              }
          }
          return true;
      }
  }
  // Digit conversions
  const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';
  const BI_RC = [];
  let rr, vv;
  rr = '0'.charCodeAt(0);
  for (vv = 0; vv <= 9; ++vv)
      BI_RC[rr++] = vv;
  rr = 'a'.charCodeAt(0);
  for (vv = 10; vv < 36; ++vv)
      BI_RC[rr++] = vv;
  rr = 'A'.charCodeAt(0);
  for (vv = 10; vv < 36; ++vv)
      BI_RC[rr++] = vv;
  function int2char(n) {
      return BI_RM.charAt(n);
  }
  function intAt(s, i) {
      const c = BI_RC[s.charCodeAt(i)];
      return c == null ? -1 : c;
  }
  // returns bit length of the integer x
  function nbits(x) {
      let r = 1, t;
      if ((t = x >>> 16) !== 0) {
          x = t;
          r += 16;
      }
      if ((t = x >> 8) !== 0) {
          x = t;
          r += 8;
      }
      if ((t = x >> 4) !== 0) {
          x = t;
          r += 4;
      }
      if ((t = x >> 2) !== 0) {
          x = t;
          r += 2;
      }
      if ((t = x >> 1) !== 0) {
          // x = t
          r += 1;
      }
      return r;
  }
  // Modular reduction using "classic" algorithm
  class Classic {
      m;
      constructor(m) {
          this.m = m;
      }
      convert(x) {
          if (x.s < 0 || x.compareTo(this.m) >= 0)
              return x.mod(this.m);
          else
              return x;
      }
      revert(x) {
          return x;
      }
      reduce(x) {
          x.divRemTo(this.m, undefined, x);
      }
      mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
      }
      sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
      }
  }
  // Montgomery reduction
  class Montgomery {
      m;
      mp;
      mpl;
      mph;
      um;
      mt2;
      constructor(m) {
          this.m = m;
          this.mp = m.invDigit();
          this.mpl = this.mp & 0x7fff;
          this.mph = this.mp >> 15;
          this.um = (1 << (BigInteger.DB - 15)) - 1;
          this.mt2 = 2 * m.t;
      }
      // xR mod m
      convert(x) {
          const r = new BigInteger();
          x.abs().dlShiftTo(this.m.t, r);
          r.divRemTo(this.m, undefined, r);
          if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
              this.m.subTo(r, r);
          return r;
      }
      // x/R mod m
      revert(x) {
          const r = new BigInteger();
          x.copyTo(r);
          this.reduce(r);
          return r;
      }
      // x = x/R mod m (HAC 14.32)
      reduce(x) {
          while (x.t <= this.mt2)
              // pad x so am has enough room later
              x[x.t++] = 0;
          for (let i = 0; i < this.m.t; ++i) {
              // faster way of calculating u0 = x[i]*mp mod DV
              let j = x[i] & 0x7fff;
              const u0 = (j * this.mpl +
                  (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) &
                  BigInteger.DM;
              // use am to combine the multiply-shift-add into one call
              j = i + this.m.t;
              x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
              // propagate carry
              while (x[j] >= BigInteger.DV) {
                  x[j] -= BigInteger.DV;
                  x[++j]++;
              }
          }
          x.clamp();
          x.drShiftTo(this.m.t, x);
          if (x.compareTo(this.m) >= 0)
              x.subTo(this.m, x);
      }
      // r = "x^2/R mod m"; x !== r
      sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
      }
      // r = "xy/R mod m"; x,y !== r
      mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
      }
  }
  // return index of lowest 1-bit in x, x < 2^31
  function lbit(x) {
      if (x === 0)
          return -1;
      let r = 0;
      if ((x & 0xffff) === 0) {
          x >>= 16;
          r += 16;
      }
      if ((x & 0xff) === 0) {
          x >>= 8;
          r += 8;
      }
      if ((x & 0xf) === 0) {
          x >>= 4;
          r += 4;
      }
      if ((x & 3) === 0) {
          x >>= 2;
          r += 2;
      }
      if ((x & 1) === 0)
          ++r;
      return r;
  }
  // return number of 1 bits in x
  function cbit(x) {
      let r = 0;
      while (x !== 0) {
          x &= x - 1;
          ++r;
      }
      return r;
  }
  // A "null" reducer
  class NullExp {
      convert = nNop;
      revert = nNop;
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      reduce = () => { };
      mulTo(x, y, r) {
          x.multiplyTo(y, r);
      }
      sqrTo(x, r) {
          x.squareTo(r);
      }
  }
  function nNop(x) {
      return x;
  }
  // Barrett modular reduction
  class Barrett {
      r2;
      q3;
      mu;
      m;
      constructor(m) {
          // setup Barrett
          this.r2 = new BigInteger();
          this.q3 = new BigInteger();
          BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
          this.mu = this.r2.divide(m);
          this.m = m;
      }
      convert(x) {
          if (x.s < 0 || x.t > 2 * this.m.t)
              return x.mod(this.m);
          else if (x.compareTo(this.m) < 0)
              return x;
          else {
              const r = new BigInteger();
              x.copyTo(r);
              this.reduce(r);
              return r;
          }
      }
      revert(x) {
          return x;
      }
      // x = x mod m (HAC 14.42)
      reduce(x) {
          x.drShiftTo(this.m.t - 1, this.r2);
          if (x.t > this.m.t + 1) {
              x.t = this.m.t + 1;
              x.clamp();
          }
          this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
          this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
          while (x.compareTo(this.r2) < 0)
              x.dAddOffset(1, this.m.t + 1);
          x.subTo(this.r2, x);
          while (x.compareTo(this.m) >= 0)
              x.subTo(this.m, x);
      }
      // r = x^2 mod m; x !== r
      sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
      }
      // r = x*y mod m; x,y !== r
      mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
      }
  }

  // From: https://github.com/tracker1/cryptico-js/blob/57b32417967b9c9b75c47c04971f72a120b59a67/src/hash.js
  /**
   *
   *  Secure Hash Algorithm (SHA256)
   *  http://www.webtoolkit.info/
   *
   *  Original code by Angel Marin, Paul Johnston.
   *
   **/
  function SHA256(msg) {
      const chrsz = 8;
      function safe_add(x, y) {
          const lsw = (x & 0xffff) + (y & 0xffff);
          const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
          return (msw << 16) | (lsw & 0xffff);
      }
      function S(X, n) {
          return (X >>> n) | (X << (32 - n));
      }
      function R(X, n) {
          return X >>> n;
      }
      function Ch(x, y, z) {
          return (x & y) ^ (~x & z);
      }
      function Maj(x, y, z) {
          return (x & y) ^ (x & z) ^ (y & z);
      }
      function Sigma0256(x) {
          return S(x, 2) ^ S(x, 13) ^ S(x, 22);
      }
      function Sigma1256(x) {
          return S(x, 6) ^ S(x, 11) ^ S(x, 25);
      }
      function Gamma0256(x) {
          return S(x, 7) ^ S(x, 18) ^ R(x, 3);
      }
      function Gamma1256(x) {
          return S(x, 17) ^ S(x, 19) ^ R(x, 10);
      }
      function core_sha256(m, l) {
          const K = [
              0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
              0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
              0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
              0xfc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
              0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
              0x6ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
              0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
              0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
              0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
              0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
              0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
          ];
          const HASH = [
              0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
              0x1f83d9ab, 0x5be0cd19,
          ];
          const W = new Array(64);
          let a, b, c, d, e, f, g, h;
          let T1, T2;
          m[l >> 5] |= 0x80 << (24 - (l % 32));
          m[(((l + 64) >> 9) << 4) + 15] = l;
          for (let i = 0; i < m.length; i += 16) {
              a = HASH[0];
              b = HASH[1];
              c = HASH[2];
              d = HASH[3];
              e = HASH[4];
              f = HASH[5];
              g = HASH[6];
              h = HASH[7];
              for (let j = 0; j < 64; j++) {
                  if (j < 16)
                      W[j] = m[j + i];
                  else
                      W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
                  T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                  T2 = safe_add(Sigma0256(a), Maj(a, b, c));
                  h = g;
                  g = f;
                  f = e;
                  e = safe_add(d, T1);
                  d = c;
                  c = b;
                  b = a;
                  a = safe_add(T1, T2);
              }
              HASH[0] = safe_add(a, HASH[0]);
              HASH[1] = safe_add(b, HASH[1]);
              HASH[2] = safe_add(c, HASH[2]);
              HASH[3] = safe_add(d, HASH[3]);
              HASH[4] = safe_add(e, HASH[4]);
              HASH[5] = safe_add(f, HASH[5]);
              HASH[6] = safe_add(g, HASH[6]);
              HASH[7] = safe_add(h, HASH[7]);
          }
          return HASH;
      }
      function str2binb(str) {
          const bin = [];
          const mask = (1 << chrsz) - 1;
          for (let i = 0; i < str.length * chrsz; i += chrsz) {
              bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - (i % 32));
          }
          return bin;
      }
      function binb2hex(binarray) {
          const hex_tab = '0123456789abcdef';
          let str = '';
          for (let i = 0; i < binarray.length * 4; i++) {
              str +=
                  hex_tab.charAt((binarray[i >> 2] >> ((3 - (i % 4)) * 8 + 4)) & 0xf) +
                      hex_tab.charAt((binarray[i >> 2] >> ((3 - (i % 4)) * 8)) & 0xf);
          }
          return str;
      }
      msg = Utf8Encode(msg);
      return binb2hex(core_sha256(str2binb(msg), msg.length * chrsz));
  }
  const sha256 = {
      hex: ((msg) => SHA256(msg)),
  };
  /**
   *
   *  Secure Hash Algorithm (SHA1)
   *  http://www.webtoolkit.info/
   *
   **/
  function SHA1(msg) {
      function rotate_left(n, s) {
          const t4 = (n << s) | (n >>> (32 - s));
          return t4;
      }
      // function lsb_hex(val: number): string {
      //   let str = ''
      //   let vh
      //   let vl
      //
      //   for (let i = 0; i <= 6; i += 2) {
      //     vh = (val >>> (i * 4 + 4)) & 0x0f
      //     vl = (val >>> (i * 4)) & 0x0f
      //     str += vh.toString(16) + vl.toString(16)
      //   }
      //   return str
      // }
      function cvt_hex(val) {
          let str = '';
          let v;
          for (let i = 7; i >= 0; i--) {
              v = (val >>> (i * 4)) & 0x0f;
              str += v.toString(16);
          }
          return str;
      }
      let blockstart;
      let i, j;
      const W = new Array(80);
      let H0 = 0x67452301;
      let H1 = 0xefcdab89;
      let H2 = 0x98badcfe;
      let H3 = 0x10325476;
      let H4 = 0xc3d2e1f0;
      let A, B, C, D, E;
      let temp;
      msg = Utf8Encode(msg);
      const msg_len = msg.length;
      const word_array = [];
      for (i = 0; i < msg_len - 3; i += 4) {
          j =
              (msg.charCodeAt(i) << 24) |
                  (msg.charCodeAt(i + 1) << 16) |
                  (msg.charCodeAt(i + 2) << 8) |
                  msg.charCodeAt(i + 3);
          word_array.push(j);
      }
      switch (msg_len % 4) {
          case 0:
              i = 0x080000000;
              break;
          case 1:
              i = (msg.charCodeAt(msg_len - 1) << 24) | 0x0800000;
              break;
          case 2:
              i =
                  (msg.charCodeAt(msg_len - 2) << 24) |
                      (msg.charCodeAt(msg_len - 1) << 16) |
                      0x08000;
              break;
          case 3:
              i =
                  (msg.charCodeAt(msg_len - 3) << 24) |
                      (msg.charCodeAt(msg_len - 2) << 16) |
                      (msg.charCodeAt(msg_len - 1) << 8) |
                      0x80;
              break;
      }
      word_array.push(i);
      while (word_array.length % 16 !== 14)
          word_array.push(0);
      word_array.push(msg_len >>> 29);
      word_array.push((msg_len << 3) & 0x0ffffffff);
      for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
          for (i = 0; i < 16; i++)
              W[i] = word_array[blockstart + i];
          for (i = 16; i <= 79; i++)
              W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
          A = H0;
          B = H1;
          C = H2;
          D = H3;
          E = H4;
          for (i = 0; i <= 19; i++) {
              temp =
                  (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5a827999) &
                      0x0ffffffff;
              E = D;
              D = C;
              C = rotate_left(B, 30);
              B = A;
              A = temp;
          }
          for (i = 20; i <= 39; i++) {
              temp =
                  (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ed9eba1) & 0x0ffffffff;
              E = D;
              D = C;
              C = rotate_left(B, 30);
              B = A;
              A = temp;
          }
          for (i = 40; i <= 59; i++) {
              temp =
                  (rotate_left(A, 5) +
                      ((B & C) | (B & D) | (C & D)) +
                      E +
                      W[i] +
                      0x8f1bbcdc) &
                      0x0ffffffff;
              E = D;
              D = C;
              C = rotate_left(B, 30);
              B = A;
              A = temp;
          }
          for (i = 60; i <= 79; i++) {
              temp =
                  (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xca62c1d6) & 0x0ffffffff;
              E = D;
              D = C;
              C = rotate_left(B, 30);
              B = A;
              A = temp;
          }
          H0 = (H0 + A) & 0x0ffffffff;
          H1 = (H1 + B) & 0x0ffffffff;
          H2 = (H2 + C) & 0x0ffffffff;
          H3 = (H3 + D) & 0x0ffffffff;
          H4 = (H4 + E) & 0x0ffffffff;
      }
      const ret = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
      return ret.toLowerCase();
  }
  const sha1 = {
      hex: SHA1,
  };
  /**
   *
   *  MD5 (Message-Digest Algorithm)
   *  http://www.webtoolkit.info/
   *
   **/
  function MD5(msg) {
      function RotateLeft(lValue, iShiftBits) {
          return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
      }
      function AddUnsigned(lX, lY) {
          const lX8 = lX & 0x80000000;
          const lY8 = lY & 0x80000000;
          const lX4 = lX & 0x40000000;
          const lY4 = lY & 0x40000000;
          const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
          if (lX4 & lY4) {
              return lResult ^ 0x80000000 ^ lX8 ^ lY8;
          }
          if (lX4 | lY4) {
              if (lResult & 0x40000000) {
                  return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
              }
              else {
                  return lResult ^ 0x40000000 ^ lX8 ^ lY8;
              }
          }
          else {
              return lResult ^ lX8 ^ lY8;
          }
      }
      function F(x, y, z) {
          return (x & y) | (~x & z);
      }
      function G(x, y, z) {
          return (x & z) | (y & ~z);
      }
      function H(x, y, z) {
          return x ^ y ^ z;
      }
      function I(x, y, z) {
          return y ^ (x | ~z);
      }
      function FF(a, b, c, d, x, s, ac) {
          a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
          return AddUnsigned(RotateLeft(a, s), b);
      }
      function GG(a, b, c, d, x, s, ac) {
          a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
          return AddUnsigned(RotateLeft(a, s), b);
      }
      function HH(a, b, c, d, x, s, ac) {
          a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
          return AddUnsigned(RotateLeft(a, s), b);
      }
      function II(a, b, c, d, x, s, ac) {
          a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
          return AddUnsigned(RotateLeft(a, s), b);
      }
      function ConvertToWordArray(str) {
          let lWordCount;
          const lMessageLength = str.length;
          const lNumberOfWords_temp1 = lMessageLength + 8;
          const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
          const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
          const lWordArray = Array(lNumberOfWords - 1);
          let lBytePosition = 0;
          let lByteCount = 0;
          while (lByteCount < lMessageLength) {
              lWordCount = (lByteCount - (lByteCount % 4)) / 4;
              lBytePosition = (lByteCount % 4) * 8;
              lWordArray[lWordCount] =
                  lWordArray[lWordCount] | (str.charCodeAt(lByteCount) << lBytePosition);
              lByteCount++;
          }
          lWordCount = (lByteCount - (lByteCount % 4)) / 4;
          lBytePosition = (lByteCount % 4) * 8;
          lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
          lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
          lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
          return lWordArray;
      }
      function WordToHex(lValue) {
          let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
          for (lCount = 0; lCount <= 3; lCount++) {
              lByte = (lValue >>> (lCount * 8)) & 255;
              WordToHexValue_temp = '0' + lByte.toString(16);
              WordToHexValue =
                  WordToHexValue +
                      WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
          }
          return WordToHexValue;
      }
      let k, AA, BB, CC, DD, a, b, c, d;
      const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
      const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
      const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
      const S41 = 6, S42 = 10, S43 = 15, S44 = 21;
      msg = Utf8Encode(msg);
      const x = ConvertToWordArray(msg);
      a = 0x67452301;
      b = 0xefcdab89;
      c = 0x98badcfe;
      d = 0x10325476;
      for (k = 0; k < x.length; k += 16) {
          AA = a;
          BB = b;
          CC = c;
          DD = d;
          a = FF(a, b, c, d, x[k + 0], S11, 0xd76aa478);
          d = FF(d, a, b, c, x[k + 1], S12, 0xe8c7b756);
          c = FF(c, d, a, b, x[k + 2], S13, 0x242070db);
          b = FF(b, c, d, a, x[k + 3], S14, 0xc1bdceee);
          a = FF(a, b, c, d, x[k + 4], S11, 0xf57c0faf);
          d = FF(d, a, b, c, x[k + 5], S12, 0x4787c62a);
          c = FF(c, d, a, b, x[k + 6], S13, 0xa8304613);
          b = FF(b, c, d, a, x[k + 7], S14, 0xfd469501);
          a = FF(a, b, c, d, x[k + 8], S11, 0x698098d8);
          d = FF(d, a, b, c, x[k + 9], S12, 0x8b44f7af);
          c = FF(c, d, a, b, x[k + 10], S13, 0xffff5bb1);
          b = FF(b, c, d, a, x[k + 11], S14, 0x895cd7be);
          a = FF(a, b, c, d, x[k + 12], S11, 0x6b901122);
          d = FF(d, a, b, c, x[k + 13], S12, 0xfd987193);
          c = FF(c, d, a, b, x[k + 14], S13, 0xa679438e);
          b = FF(b, c, d, a, x[k + 15], S14, 0x49b40821);
          a = GG(a, b, c, d, x[k + 1], S21, 0xf61e2562);
          d = GG(d, a, b, c, x[k + 6], S22, 0xc040b340);
          c = GG(c, d, a, b, x[k + 11], S23, 0x265e5a51);
          b = GG(b, c, d, a, x[k + 0], S24, 0xe9b6c7aa);
          a = GG(a, b, c, d, x[k + 5], S21, 0xd62f105d);
          d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
          c = GG(c, d, a, b, x[k + 15], S23, 0xd8a1e681);
          b = GG(b, c, d, a, x[k + 4], S24, 0xe7d3fbc8);
          a = GG(a, b, c, d, x[k + 9], S21, 0x21e1cde6);
          d = GG(d, a, b, c, x[k + 14], S22, 0xc33707d6);
          c = GG(c, d, a, b, x[k + 3], S23, 0xf4d50d87);
          b = GG(b, c, d, a, x[k + 8], S24, 0x455a14ed);
          a = GG(a, b, c, d, x[k + 13], S21, 0xa9e3e905);
          d = GG(d, a, b, c, x[k + 2], S22, 0xfcefa3f8);
          c = GG(c, d, a, b, x[k + 7], S23, 0x676f02d9);
          b = GG(b, c, d, a, x[k + 12], S24, 0x8d2a4c8a);
          a = HH(a, b, c, d, x[k + 5], S31, 0xfffa3942);
          d = HH(d, a, b, c, x[k + 8], S32, 0x8771f681);
          c = HH(c, d, a, b, x[k + 11], S33, 0x6d9d6122);
          b = HH(b, c, d, a, x[k + 14], S34, 0xfde5380c);
          a = HH(a, b, c, d, x[k + 1], S31, 0xa4beea44);
          d = HH(d, a, b, c, x[k + 4], S32, 0x4bdecfa9);
          c = HH(c, d, a, b, x[k + 7], S33, 0xf6bb4b60);
          b = HH(b, c, d, a, x[k + 10], S34, 0xbebfbc70);
          a = HH(a, b, c, d, x[k + 13], S31, 0x289b7ec6);
          d = HH(d, a, b, c, x[k + 0], S32, 0xeaa127fa);
          c = HH(c, d, a, b, x[k + 3], S33, 0xd4ef3085);
          b = HH(b, c, d, a, x[k + 6], S34, 0x4881d05);
          a = HH(a, b, c, d, x[k + 9], S31, 0xd9d4d039);
          d = HH(d, a, b, c, x[k + 12], S32, 0xe6db99e5);
          c = HH(c, d, a, b, x[k + 15], S33, 0x1fa27cf8);
          b = HH(b, c, d, a, x[k + 2], S34, 0xc4ac5665);
          a = II(a, b, c, d, x[k + 0], S41, 0xf4292244);
          d = II(d, a, b, c, x[k + 7], S42, 0x432aff97);
          c = II(c, d, a, b, x[k + 14], S43, 0xab9423a7);
          b = II(b, c, d, a, x[k + 5], S44, 0xfc93a039);
          a = II(a, b, c, d, x[k + 12], S41, 0x655b59c3);
          d = II(d, a, b, c, x[k + 3], S42, 0x8f0ccc92);
          c = II(c, d, a, b, x[k + 10], S43, 0xffeff47d);
          b = II(b, c, d, a, x[k + 1], S44, 0x85845dd1);
          a = II(a, b, c, d, x[k + 8], S41, 0x6fa87e4f);
          d = II(d, a, b, c, x[k + 15], S42, 0xfe2ce6e0);
          c = II(c, d, a, b, x[k + 6], S43, 0xa3014314);
          b = II(b, c, d, a, x[k + 13], S44, 0x4e0811a1);
          a = II(a, b, c, d, x[k + 4], S41, 0xf7537e82);
          d = II(d, a, b, c, x[k + 11], S42, 0xbd3af235);
          c = II(c, d, a, b, x[k + 2], S43, 0x2ad7d2bb);
          b = II(b, c, d, a, x[k + 9], S44, 0xeb86d391);
          a = AddUnsigned(a, AA);
          b = AddUnsigned(b, BB);
          c = AddUnsigned(c, CC);
          d = AddUnsigned(d, DD);
      }
      const temp = WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d);
      return temp.toLowerCase();
  }
  function Utf8Encode(str) {
      str = str.replace(/\r\n/g, '\n');
      let utftext = '';
      for (let n = 0; n < str.length; n++) {
          const c = str.charCodeAt(n);
          if (c < 128) {
              utftext += String.fromCharCode(c);
          }
          else if (c > 127 && c < 2048) {
              utftext += String.fromCharCode((c >> 6) | 192);
              utftext += String.fromCharCode((c & 63) | 128);
          }
          else {
              utftext += String.fromCharCode((c >> 12) | 224);
              utftext += String.fromCharCode(((c >> 6) & 63) | 128);
              utftext += String.fromCharCode((c & 63) | 128);
          }
      }
      return utftext;
  }

  // Depends on jsbn.js and rng.js
  function parseBigInt(str, r) {
      return new BigInteger(str, r);
  }
  function linebrk(s, n) {
      let ret = '';
      let i = 0;
      while (i + n < s.length) {
          ret += s.substring(i, i + n) + '\n';
          i += n;
      }
      return ret + s.substring(i, s.length);
  }
  function byte2Hex(b) {
      if (b < 0x10)
          return '0' + b.toString(16);
      else
          return b.toString(16);
  }
  // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
  function pkcs1pad2(s, n) {
      if (n < s.length + 11) {
          // TODO: fix for utf-8
          //throw "Message too long for RSA (n=" + n + ", l=" + s.length + ")"
          //return null;
          throw 'Message too long for RSA (n=' + n + ', l=' + s.length + ')';
      }
      const ba = [];
      let i = s.length - 1;
      while (i >= 0 && n > 0) {
          const c = s.charCodeAt(i--);
          if (c < 128) {
              // encode using utf-8
              ba[--n] = c;
          }
          else if (c > 127 && c < 2048) {
              ba[--n] = (c & 63) | 128;
              ba[--n] = (c >> 6) | 192;
          }
          else {
              ba[--n] = (c & 63) | 128;
              ba[--n] = ((c >> 6) & 63) | 128;
              ba[--n] = (c >> 12) | 224;
          }
      }
      ba[--n] = 0;
      const rng = new SecureRandom();
      const x = [];
      while (n > 2) {
          // random non-zero pad
          x[0] = 0;
          while (x[0] === 0)
              rng.nextBytes(x);
          ba[--n] = x[0];
      }
      ba[--n] = 2;
      ba[--n] = 0;
      return new BigInteger(ba);
  }
  // "empty" RSA key constructor
  class RSAKey {
      n = new BigInteger();
      e = 0;
      d = new BigInteger();
      p = new BigInteger();
      q = new BigInteger();
      dmp1 = new BigInteger();
      dmq1 = new BigInteger();
      coeff = new BigInteger();
      // Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
      // encryptB64(text: string): string | null {
      //   const h = this.encrypt(text)
      //   if (h) return hex2b64(h)
      //   else return null
      // }
      // Set the public key fields N and e from hex strings
      setPublic(N, E) {
          if (N && E) {
              this.n = parseBigInt(N, 16);
              this.e = parseInt(E, 16);
          }
          else
              throw 'Invalid RSA public key';
      }
      // Perform raw public operation on "x": return x^e (mod n)
      doPublic(x) {
          return x.modPowInt(this.e, this.n);
      }
      // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
      encrypt(text) {
          const m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
          // if (!m) return null
          const c = this.doPublic(m);
          // if (!c) return null
          const h = c.toString(16);
          if ((h.length & 1) === 0)
              return h;
          else
              return '0' + h;
      }
      // Set the private key fields N, e, and d from hex strings
      setPrivate(N, E, D) {
          if (!N && !E && N.length > 0 && E.length > 0) {
              this.n = parseBigInt(N, 16);
              this.e = parseInt(E, 16);
              this.d = parseBigInt(D, 16);
          }
          else
              throw 'Invalid RSA private key';
      }
      // Set the private key fields N, e, d and CRT params from hex strings
      setPrivateEx(N, E, D, P, Q, DP, DQ, C) {
          if (!N && !E && N.length > 0 && E.length > 0) {
              this.n = parseBigInt(N, 16);
              this.e = parseInt(E, 16);
              this.d = parseBigInt(D, 16);
              this.p = parseBigInt(P, 16);
              this.q = parseBigInt(Q, 16);
              this.dmp1 = parseBigInt(DP, 16);
              this.dmq1 = parseBigInt(DQ, 16);
              this.coeff = parseBigInt(C, 16);
          }
          else
              throw new Error('Invalid RSA private key');
      }
      // Generate a new random private key B bits long, using public expt E
      generate(B, E) {
          const rng = new SeededRandom();
          const qs = B >> 1;
          this.e = parseInt(E, 16);
          const ee = new BigInteger(E, 16);
          for (;;) {
              for (;;) {
                  this.p = new BigInteger(B - qs, 1, rng);
                  if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) ===
                      0 &&
                      this.p.isProbablePrime(10))
                      break;
              }
              for (;;) {
                  this.q = new BigInteger(qs, 1, rng);
                  if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) ===
                      0 &&
                      this.q.isProbablePrime(10))
                      break;
              }
              if (this.p.compareTo(this.q) <= 0) {
                  const t = this.p;
                  this.p = this.q;
                  this.q = t;
              }
              const p1 = this.p.subtract(BigInteger.ONE);
              const q1 = this.q.subtract(BigInteger.ONE);
              const phi = p1.multiply(q1);
              if (phi.gcd(ee).compareTo(BigInteger.ONE) === 0) {
                  this.n = this.p.multiply(this.q);
                  this.d = ee.modInverse(phi);
                  this.dmp1 = this.d.mod(p1);
                  this.dmq1 = this.d.mod(q1);
                  this.coeff = this.q.modInverse(this.p);
                  break;
              }
          }
      }
      // Perform raw private operation on "x": return x^d (mod n)
      doPrivate(x) {
          if (!this.p || !this.q)
              return x.modPow(this.d, this.n);
          // TODO: re-calculate any missing CRT params
          let xp = x.mod(this.p).modPow(this.dmp1, this.p);
          const xq = x.mod(this.q).modPow(this.dmq1, this.q);
          while (xp.compareTo(xq) < 0)
              xp = xp.add(this.p);
          return xp
              .subtract(xq)
              .multiply(this.coeff)
              .mod(this.p)
              .multiply(this.q)
              .add(xq);
      }
      // Return the PKCS#1 RSA decryption of "ctext".
      // "ctext" is an even-length hex string and the output is a plain string.
      decrypt(ctext) {
          const c = parseBigInt(ctext, 16);
          const m = this.doPrivate(c);
          if (!(m instanceof BigInteger))
              return null;
          return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
      }
      signString = _rsasign_signString;
      signStringWithSHA1 = _rsasign_signStringWithSHA1;
      signStringWithSHA256 = _rsasign_signStringWithSHA256;
      verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
      verifyString = _rsasign_verifyString;
      toJSON() {
          return JSON.stringify({
              coeff: this.coeff.toString(16),
              d: this.d.toString(16),
              dmp1: this.dmp1.toString(16),
              dmq1: this.dmq1.toString(16),
              e: this.e.toString(16),
              n: this.n.toString(16),
              p: this.p.toString(16),
              q: this.q.toString(16),
          });
      }
      static parse(key) {
          const json = (typeof key === 'string' ? JSON.parse(key) : key);
          if (!json) {
              return null;
          }
          const rsa = new RSAKey();
          rsa.setPrivateEx(json.n, json.e, json.d, json.p, json.q, json.dmp1, json.dmq1, json.coeff);
          return rsa;
      }
  }
  // Version 1.1: support utf-8 decoding in pkcs1unpad2
  // Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
  function pkcs1unpad2(d, n) {
      const b = d.toByteArray();
      let i = 0;
      while (i < b.length && b[i] === 0)
          ++i;
      if (b.length - i !== n - 1 || b[i] !== 2)
          return null;
      ++i;
      while (b[i] !== 0)
          if (++i >= b.length)
              return null;
      let ret = '';
      while (++i < b.length) {
          const c = b[i] & 255;
          if (c < 128) {
              // utf-8 decode
              ret += String.fromCharCode(c);
          }
          else if (c > 191 && c < 224) {
              ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
              ++i;
          }
          else {
              ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
              i += 2;
          }
      }
      return ret;
  }
  //
  // rsa-sign.js - adding signing functions to RSAKey class.
  //
  //
  // version: 1.0 (2010-Jun-03)
  //
  // Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
  //
  // This software is licensed under the terms of the MIT License.
  // http://www.opensource.org/licenses/mit-license.php
  //
  // The above copyright and license notice shall be
  // included in all copies or substantial portions of the Software.
  //
  // Depends on:
  //   function sha1.hex(s) of sha1.js
  //   jsbn.js
  //   jsbn2.js
  //   rsa.js
  //   rsa2.js
  //
  // keysize / pmstrlen
  //  512 /  128
  // 1024 /  256
  // 2048 /  512
  // 4096 / 1024
  // As for _RSASGIN_DIHEAD values for each hash algorithm, see PKCS#1 v2.1 spec (p38).
  const _RSASIGN_DIHEAD = {
      sha1: '3021300906052b0e03021a05000414',
      sha256: '3031300d060960864801650304020105000420',
      // md2: '3020300c06082a864886f70d020205000410',
      // md5: '3020300c06082a864886f70d020505000410',
      // sha384: '3041300d060960864801650304020205000430',
      // sha512: '3051300d060960864801650304020305000440',
  };
  const _RSASIGN_HASHHEXFUNC = {
      sha1: sha1.hex,
      sha256: sha256.hex,
  };
  // ========================================================================
  // Signature Generation
  // ========================================================================
  function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
      const pmStrLen = keySize / 4;
      const hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
      const sHashHex = hashFunc(s);
      const sHead = '0001';
      const sTail = '00' + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
      let sMid = '';
      const fLen = pmStrLen - sHead.length - sTail.length;
      for (let i = 0; i < fLen; i += 2) {
          sMid += 'ff';
      }
      const sPaddedMessageHex = sHead + sMid + sTail;
      return sPaddedMessageHex;
  }
  function _rsasign_signString(s, hashAlg) {
      const hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
      const biPaddedMessage = parseBigInt(hPM, 16);
      const biSign = this.doPrivate(biPaddedMessage);
      const hexSign = biSign.toString(16);
      return hexSign;
  }
  function _rsasign_signStringWithSHA1(s) {
      const hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha1');
      const biPaddedMessage = parseBigInt(hPM, 16);
      const biSign = this.doPrivate(biPaddedMessage);
      const hexSign = biSign.toString(16);
      return hexSign;
  }
  function _rsasign_signStringWithSHA256(s) {
      const hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha256');
      const biPaddedMessage = parseBigInt(hPM, 16);
      const biSign = this.doPrivate(biPaddedMessage);
      const hexSign = biSign.toString(16);
      return hexSign;
  }
  // ========================================================================
  // Signature Verification
  // ========================================================================
  function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
      const rsa = new RSAKey();
      rsa.setPublic(hN, hE);
      const biDecryptedSig = rsa.doPublic(biSig);
      return biDecryptedSig;
  }
  function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
      const biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
      const hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
      return hDigestInfo;
  }
  function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
      for (const algName in _RSASIGN_DIHEAD) {
          const head = _RSASIGN_DIHEAD[algName];
          const len = head.length;
          if (hDigestInfo.substring(0, len) === head) {
              return [algName, hDigestInfo.substring(len)];
          }
      }
      return [];
  }
  function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
      const hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
      const digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
      if (digestInfoAry.length === 0)
          return false;
      const algName = digestInfoAry[0];
      const diHashValue = digestInfoAry[1];
      const ff = _RSASIGN_HASHHEXFUNC[algName];
      const msgHashValue = ff(sMsg);
      return diHashValue === msgHashValue;
  }
  function _rsasign_verifyHexSignatureForMessage(sMsg, hSig) {
      const biSig = parseBigInt(hSig, 16);
      const result = _rsasign_verifySignatureWithArgs(sMsg, biSig, this.n.toString(16), this.e.toString(16));
      return result;
  }
  function _rsasign_verifyString(sMsg, hSig) {
      hSig = hSig.replace(/[ \n]+/g, '');
      const biSig = parseBigInt(hSig, 16);
      const biDecryptedSig = this.doPublic(biSig);
      const hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
      const digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
      if (digestInfoAry.length === 0)
          return false;
      const algName = digestInfoAry[0];
      const diHashValue = digestInfoAry[1];
      const ff = _RSASIGN_HASHHEXFUNC[algName];
      const msgHashValue = ff(sMsg);
      return diHashValue === msgHashValue;
  }

  const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const magic = '::52cee64bb3a38f6403386519a39ac91c::';
  aes.Init();
  class cryptico {
      static b256to64(t) {
          let a = 0, // Should be reassigned before read
          c, n;
          let r = '', 
          // l = 0,
          s = 0;
          const tl = t.length;
          for (n = 0; n < tl; n++) {
              c = t.charCodeAt(n);
              if (s === 0) {
                  r += base64Chars.charAt((c >> 2) & 63);
                  a = (c & 3) << 4;
              }
              else if (s === 1) {
                  r += base64Chars.charAt(a | ((c >> 4) & 15));
                  a = (c & 15) << 2;
              }
              else if (s === 2) {
                  r += base64Chars.charAt(a | ((c >> 6) & 3));
                  // l += 1
                  r += base64Chars.charAt(c & 63);
              }
              // l += 1
              s += 1;
              if (s === 3)
                  s = 0;
          }
          if (s > 0) {
              r += base64Chars.charAt(a);
              // l += 1
              r += '=';
              // l += 1
          }
          if (s === 1) {
              r += '=';
          }
          return r;
      }
      static b64to256(t) {
          let c, n;
          let r = '', s = 0, a = 0;
          const tl = t.length;
          for (n = 0; n < tl; n++) {
              c = base64Chars.indexOf(t.charAt(n));
              if (c >= 0) {
                  if (s)
                      r += String.fromCharCode(a | ((c >> (6 - s)) & 255));
                  s = (s + 2) & 7;
                  a = (c << s) & 255;
              }
          }
          return r;
      }
      static b16to64(h) {
          let i;
          let c;
          let ret = '';
          if (h.length % 2 === 1) {
              h = '0' + h;
          }
          for (i = 0; i + 3 <= h.length; i += 3) {
              c = parseInt(h.substring(i, i + 3), 16);
              ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63);
          }
          if (i + 1 === h.length) {
              c = parseInt(h.substring(i, i + 1), 16);
              ret += base64Chars.charAt(c << 2);
          }
          else if (i + 2 === h.length) {
              c = parseInt(h.substring(i, i + 2), 16);
              ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4);
          }
          while ((ret.length & 3) > 0)
              ret += '=';
          return ret;
      }
      static b64to16(s) {
          let ret = '';
          let i;
          let k = 0;
          let slop = 0; // Should be reassigned before read
          for (i = 0; i < s.length; ++i) {
              if (s.charAt(i) === '=')
                  break;
              const v = base64Chars.indexOf(s.charAt(i));
              if (v < 0)
                  continue;
              if (k === 0) {
                  ret += int2char(v >> 2);
                  slop = v & 3;
                  k = 1;
              }
              else if (k === 1) {
                  ret += int2char((slop << 2) | (v >> 4));
                  slop = v & 0xf;
                  k = 2;
              }
              else if (k === 2) {
                  ret += int2char(slop);
                  ret += int2char(v >> 2);
                  slop = v & 3;
                  k = 3;
              }
              else {
                  ret += int2char((slop << 2) | (v >> 4));
                  ret += int2char(v & 0xf);
                  k = 0;
              }
          }
          if (k === 1)
              ret += int2char(slop << 2);
          return ret;
      }
      // Converts a string to a byte array.
      static string2bytes(str) {
          const bytes = [];
          for (let i = 0; i < str.length; i++) {
              bytes.push(str.charCodeAt(i));
          }
          return bytes;
      }
      // Converts a byte array to a string.
      static bytes2string(bytes) {
          let str = '';
          for (let i = 0; i < bytes.length; i++) {
              str += String.fromCharCode(bytes[i]);
          }
          return str;
      }
      // Converts a UTF-8 string to ASCII string.
      static utf82string(str) {
          return unescape(encodeURIComponent(str));
      }
      // Converts ascii string to a UTF-8 string.
      static string2utf8(uriencoded) {
          return decodeURIComponent(escape(uriencoded));
      }
      // Converts a UTF-8 string to a byte array.
      static utf82bytes(str) {
          const uriencoded = unescape(encodeURIComponent(str));
          return this.string2bytes(uriencoded);
      }
      // Converts a byte array to a UTF-8 string.
      static bytes2utf8(bytes) {
          const uriencoded = this.bytes2string(bytes);
          return decodeURIComponent(escape(uriencoded));
      }
      // Returns a XOR b, where a and b are 16-byte byte arrays.
      static blockXOR(a, b) {
          const xor = new Array(16);
          for (let i = 0; i < 16; i++) {
              xor[i] = a[i] ^ b[i];
          }
          return xor;
      }
      // Returns a 16-byte initialization vector.
      static blockIV() {
          const r = new SecureRandom();
          const IV = new Array(16);
          r.nextBytes(IV);
          return IV;
      }
      // Returns a copy of bytes with zeros appended to the end
      // so that the (length of bytes) % 16 === 0.
      static pad16(bytes) {
          const newBytes = bytes.slice(0);
          const padding = (16 - (bytes.length % 16)) % 16;
          for (let i = bytes.length; i < bytes.length + padding; i++) {
              newBytes.push(0);
          }
          return newBytes;
      }
      // Removes trailing zeros from a byte array.
      static depad(bytes) {
          let newBytes = bytes.slice(0);
          while (newBytes[newBytes.length - 1] === 0) {
              newBytes = newBytes.slice(0, newBytes.length - 1);
          }
          return newBytes;
      }
      // AES CBC Encryption.
      static encryptAESCBC(plaintext, key) {
          const exkey = key.slice(0);
          aes.ExpandKey(exkey);
          let blocks = this.utf82bytes(plaintext);
          blocks = this.pad16(blocks);
          let encryptedBlocks = this.blockIV();
          for (let i = 0; i < blocks.length / 16; i++) {
              let tempBlock = blocks.slice(i * 16, i * 16 + 16);
              const prevBlock = encryptedBlocks.slice(i * 16, i * 16 + 16);
              tempBlock = this.blockXOR(prevBlock, tempBlock);
              aes.Encrypt(tempBlock, exkey);
              encryptedBlocks = encryptedBlocks.concat(tempBlock);
          }
          const ciphertext = this.bytes2string(encryptedBlocks);
          return this.b256to64(ciphertext);
      }
      // AES CBC Decryption.
      static decryptAESCBC(encryptedText, key) {
          const exkey = key.slice(0);
          aes.ExpandKey(exkey);
          const asciiText = this.b64to256(encryptedText);
          const encryptedBlocks = this.string2bytes(asciiText);
          let decryptedBlocks = [];
          for (let i = 1; i < encryptedBlocks.length / 16; i++) {
              let tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16);
              const prevBlock = encryptedBlocks.slice((i - 1) * 16, (i - 1) * 16 + 16);
              aes.Decrypt(tempBlock, exkey);
              tempBlock = this.blockXOR(prevBlock, tempBlock);
              decryptedBlocks = decryptedBlocks.concat(tempBlock);
          }
          decryptedBlocks = this.depad(decryptedBlocks);
          return this.bytes2utf8(decryptedBlocks);
      }
      // Wraps a str to 60 characters.
      static wrap60(str) {
          let outstr = '';
          for (let i = 0; i < str.length; i++) {
              if (i % 60 === 0 && i !== 0)
                  outstr += '\n';
              outstr += str[i];
          }
          return outstr;
      }
      // Generate a random key for the AES-encrypted message. ciphertext.split
      static generateAESKey() {
          const key = new Array(32);
          const r = new SecureRandom();
          r.nextBytes(key);
          return key;
      }
      // Generates an RSA key from a passphrase.
      static generateRSAKey(passphrase, bitlength) {
          math.seedrandom(sha256.hex(passphrase));
          const rsa = new RSAKey();
          rsa.generate(bitlength, '03');
          return rsa;
      }
      // Returns the ascii-armored version of the public key.
      static publicKeyString(rsakey) {
          return this.b16to64(rsakey.n.toString(16));
      }
      // Returns an MD5 sum of a publicKeyString for easier identification.
      static publicKeyID(publicKeyString) {
          return MD5(publicKeyString);
      }
      static publicKeyFromString(str) {
          const N = this.b64to16(str.split('|')[0]);
          const E = '03';
          const rsa = new RSAKey();
          rsa.setPublic(N, E);
          return rsa;
      }
      static encrypt(plaintext, publickeystring, signingkey) {
          {
              let cipherblock = '';
              const aeskey = this.generateAESKey();
              try {
                  const publickey = this.publicKeyFromString(publickeystring);
                  cipherblock +=
                      this.b16to64(publickey.encrypt(this.bytes2string(aeskey))) + '?';
              }
              catch (err) {
                  return { status: 'Invalid public key' };
              }
              if (signingkey) {
                  const signString = this.sign(plaintext, signingkey);
                  plaintext += magic;
                  plaintext += this.publicKeyString(signingkey);
                  plaintext += magic;
                  plaintext += signString;
              }
              cipherblock += this.encryptAESCBC(plaintext, aeskey);
              return { status: 'success', cipher: cipherblock };
          }
      }
      static decrypt(ciphertext, key) {
          const cipherblock = ciphertext.split('?');
          const aeskey = key.decrypt(this.b64to16(cipherblock[0]));
          if (aeskey == null) {
              return { status: 'failure' };
          }
          const aeskeyBytes = this.string2bytes(aeskey);
          const plaintext = this.decryptAESCBC(cipherblock[1], aeskeyBytes).split(magic);
          if (plaintext.length > 1) {
              return this._confirm(plaintext);
          }
          else
              return {
                  status: 'success',
                  plaintext: plaintext[0],
                  signature: 'unsigned',
              };
      }
      static sign(plaintext, signingkey) {
          return this.b16to64(signingkey.signString(plaintext, 'sha256'));
      }
      static verify(plaintext) {
          const result = this._confirm(plaintext);
          return result.status === 'success' && result.signature === 'verified';
      }
      static _confirm(plaintext) {
          if (plaintext.length === 3) {
              const publickey = this.publicKeyFromString(plaintext[1]);
              const signature = this.b64to16(plaintext[2]);
              if (publickey.verifyString(plaintext[0], signature)) {
                  return {
                      status: 'success',
                      plaintext: plaintext[0],
                      signature: 'verified',
                      publicKeyString: this.publicKeyString(publickey),
                  };
              }
              else {
                  return {
                      status: 'success',
                      plaintext: plaintext[0],
                      signature: 'forged',
                      publicKeyString: this.publicKeyString(publickey),
                  };
              }
          }
          else {
              return {
                  status: 'failure',
              };
          }
      }
  }

  exports.BigInteger = BigInteger;
  exports.MD5 = MD5;
  exports.RSAKey = RSAKey;
  exports.SecureRandom = SecureRandom;
  exports.SeededRandom = SeededRandom;
  exports.aes = aes;
  exports.byte2Hex = byte2Hex;
  exports.cryptico = cryptico;
  exports.int2char = int2char;
  exports.linebrk = linebrk;
  exports.math = math;
  exports.op_and = op_and;
  exports.op_andnot = op_andnot;
  exports.op_or = op_or;
  exports.op_xor = op_xor;
  exports.parseBigInt = parseBigInt;
  exports.pkcs1pad2 = pkcs1pad2;
  exports.pkcs1unpad2 = pkcs1unpad2;
  exports.sha1 = sha1;
  exports.sha256 = sha256;

  Object.defineProperty(exports, '__esModule', { value: true });

  return exports;

}({}));
//# sourceMappingURL=cryptico.iife.js.map
