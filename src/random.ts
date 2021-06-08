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

import { ByteArray } from './type'

const pool: number[] = [] // pool: entropy pool starts empty
const width = 256 // width: each RC4 output is 0 <= x < 256
const chunks = 6 // chunks: at least six RC4 outputs for each double
//
// The following constants are related to IEEE 754 limits.
//
const significance = Math.pow(2, 52) // significance: there are 52 significant digits in a double
const overflow = significance * 2
const startdenom = Math.pow(width, chunks)

export const math = {
  //
  // seedrandom()
  // This is the seedrandom function described above.
  //
  seedrandom(seed: string, use_entropy = false): string {
    const key: number[] = []

    // Flatten the seed string or build one from local entropy if needed.
    seed = mixkey(
      flatten(
        use_entropy
          ? [seed, pool]
          : arguments.length
          ? seed
          : [new Date().getTime(), pool],
        3,
      ),
      key,
    )

    // Use the seed to initialize an ARC4 generator.
    const arc4 = new ARC4(key)

    // Mix the randomness into accumulated entropy.
    mixkey(arc4.S, pool)

    // Override math.random
    // This function returns a random double in [0, 1) that contains
    // randomness in every bit of the mantissa of the IEEE 754 value.
    math.random = function (): number {
      // Closure to return a random double:
      let n = arc4.g(chunks) // Start with a numerator n < 2 ^ 48
      let d = startdenom //   and denominator d = 2 ^ 48.
      let x = 0 //   and no 'extra last byte'.
      while (n < significance) {
        // Fill up all significant digits by
        n = (n + x) * width //   shifting numerator and
        d *= width //   denominator and generating a
        x = arc4.g(1) //   new least-significant-byte.
      }
      while (n >= overflow) {
        // To avoid rounding up, before adding
        n /= 2 //   last byte, shift everything
        d /= 2 //   right using integer math until
        x >>>= 1 //   we have exactly the desired bits.
      }
      return (n + x) / d // Form the number within [0, 1).
    }

    // Return the seed that was used
    return seed
  },

  random: function (): number {
    return Math.random()
  },
}

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
  i = 0
  j = 0
  S: number[] = []
  c: number[] = []

  constructor(key: number[]) {
    let t,
      u,
      keylen = key.length
    let i = 0,
      j = 0

    // The empty key [] is treated as [0].
    if (!keylen) {
      key = [keylen++]
    }

    // Set up S using the standard key scheduling algorithm.
    while (i < width) {
      this.S[i] = i++
    }
    for (i = 0; i < width; i++) {
      t = this.S[i]
      j = lowbits(j + t + key[i % keylen])
      u = this.S[j]
      this.S[i] = u
      this.S[j] = t
    }

    // For robust unpredictability discard an initial batch of values.
    // See http://www.rsa.com/rsalabs/node.asp?id=2009
    this.g(width)
  }

  // The "g" method returns the next (count) outputs as one number.
  g(count: number): number {
    const s = this.S
    let i = lowbits(this.i + 1)
    let t = s[i]
    let j = lowbits(this.j + t)
    let u = s[j]
    s[i] = u
    s[j] = t
    let r = s[lowbits(t + u)]
    while (--count) {
      i = lowbits(i + 1)
      t = s[i]
      j = lowbits(j + t)
      u = s[j]
      s[i] = u
      s[j] = t
      r = r * width + s[lowbits(t + u)]
    }
    this.i = i
    this.j = j
    return r
  }
}

type NestedStrArray = (string | NestedStrArray)[]

//
// flatten()
// Converts an object tree to nested arrays of strings.
//
/** @param {Object=} result
 * @param {string=} prop
 * @param {string=} typ */
function flatten(obj: unknown, depth: number): NestedStrArray | string {
  const result: NestedStrArray = []
  const typ = typeof obj
  if (depth && typ === 'object') {
    for (const prop in obj as Record<string, unknown>) {
      if (prop.indexOf('S') < 5) {
        // Avoid FF3 bug (local/sessionStorage)
        try {
          result.push(
            flatten((obj as Record<string, unknown>)[prop], depth - 1),
          )
        } catch (e) {
          console.error(e)
        }
      }
    }
  }
  return result.length ? result : obj + (typ !== 'string' ? '\0' : '')
}

//
// mixkey()
// Mixes a string seed into a key that is an array of integers, and
// returns a shortened string seed that is equivalent to the result key.
//
/** @param {number=} smear
 * @param {number=} j */
function mixkey(seed: unknown, key: number[]): string {
  const seedStr = seed + '' // Ensure the seed is a string
  let smear = 0
  for (let i = 0; i < seedStr.length; i++) {
    key[lowbits(i)] = lowbits(
      (smear ^= key[lowbits(i)] * 19) + seedStr.charCodeAt(i),
    )
  }
  let mixed = ''
  key.forEach((v) => (mixed += String.fromCharCode(v)))
  return mixed
}

//
// lowbits()
// A quick "n mod width" for width a power of 2.
//
function lowbits(n: number): number {
  return n & (width - 1)
}

//
// When seedrandom.js is loaded, we immediately mix a few bits
// from the built-in RNG into the entropy pool.  Because we do
// not want to intefere with determinstic PRNG state later,
// seedrandom will not call math.random on its own again after
// initialization.
//
mixkey(Math.random(), pool)

// This is not really a random number generator object, and two SeededRandom
// objects will conflict with one another, but it's good enough for generating
// the rsa key.
export class SeededRandom {
  nextBytes(ba: number[]): void {
    for (let i = 0; i < ba.length; i++) {
      ba[i] = Math.floor(math.random() * 256)
    }
  }
}

// prng4.js - uses Arcfour as a PRNG
class Arcfour {
  i = 0
  j = 0
  S: number[] = []

  // Initialize arcfour context from key, an array of ints, each from [0..255]
  init(key: number[]): void {
    let i, j, t
    for (i = 0; i < 256; ++i) this.S[i] = i
    j = 0
    for (i = 0; i < 256; ++i) {
      j = (j + this.S[i] + key[i % key.length]) & 255
      t = this.S[i]
      this.S[i] = this.S[j]
      this.S[j] = t
    }
    this.i = 0
    this.j = 0
  }

  next(): number {
    this.i = (this.i + 1) & 255
    this.j = (this.j + this.S[this.i]) & 255
    const t = this.S[this.i]
    this.S[this.i] = this.S[this.j]
    this.S[this.j] = t
    return this.S[(t + this.S[this.i]) & 255]
  }
}

// Plug in your RNG constructor here
function prng_newstate(): Arcfour {
  return new Arcfour()
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
const rng_psize = 256

// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

let rng_state: Arcfour
let rng_pool: number[] = []
let rng_pptr: number

// Mix in a 32-bit integer into the pool
function rng_seed_int(x: number): void {
  rng_pool[rng_pptr++] ^= x & 255
  rng_pool[rng_pptr++] ^= (x >> 8) & 255
  rng_pool[rng_pptr++] ^= (x >> 16) & 255
  rng_pool[rng_pptr++] ^= (x >> 24) & 255
  if (rng_pptr >= rng_psize) rng_pptr -= rng_psize
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time(): void {
  rng_seed_int(new Date().getTime())
}

// Initialize the pool with junk if needed.
if (!rng_pool) {
  rng_pool = []
  rng_pptr = 0
  let t
  while (rng_pptr < rng_psize) {
    // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random())
    rng_pool[rng_pptr++] = t >>> 8
    rng_pool[rng_pptr++] = t & 255
  }
  rng_pptr = 0
  rng_seed_time()
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte(): number {
  if (!rng_state) {
    rng_seed_time()
    rng_state = prng_newstate()
    rng_state.init(rng_pool)
    for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0
    rng_pptr = 0
    //rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return rng_state.next()
}

export class SecureRandom {
  nextBytes(ba: ByteArray): void {
    let i
    for (i = 0; i < ba.length; ++i) ba[i] = rng_get_byte()
  }
}
