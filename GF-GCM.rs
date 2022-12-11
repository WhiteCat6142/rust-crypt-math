/*
Galois Field of GCM
F_2上の多項式環である
x^128+x^7+x^2+x+1は既約なので零因子のない、つまりa*b=a*c => b=cとなる剰余環が生成される(整域)

Galois/Counter Mode - Wikipedia
https://ja.wikipedia.org/wiki/Galois/Counter_Mode

予備知識としてのGF(2**n)
http://zakii.la.coocan.jp/signal/40_galois_field.htm

CLMUL instruction set - Wikipedia
https://ja.wikipedia.org/wiki/CLMUL_instruction_set

PCLMULQDQ - Carry-Less Multiplication Quadword
https://shell-storm.org/x86doc/PCLMULQDQ.html

u128 - Rust
https://doc.rust-lang.org/std/primitive.u128.html

Newtype - Rust Design Patterns
https://rust-unofficial.github.io/patterns/patterns/behavioural/newtype.html
*/

use std::ops::*;

pub struct GF(u128);

impl GF {
    pub fn new(x: u128) -> Self {
        Self(x)
    }
}

impl Add for GF {
    type Output = Self;
    fn add(self, GF(rhs): Self) -> Self {
        let Self(lhs) = self;
        Self(lhs ^ rhs)
    }
}

impl Sub for GF {
    type Output = Self;
    fn sub(self, GF(rhs): Self) -> Self {
        let Self(lhs) = self;
        Self(lhs ^ rhs)
    }
}

impl Mul for GF {
    type Output = Self;
    fn mul(self, GF(x0): Self) -> Self {
        let Self(z) = self;
        let mut x: u128 = x0;
        let mut y = 0u128;
        let c = 1u128 << 127;
        let d = 0b10000111;
        let mut i = x.leading_zeros();
        x <<= i;
        i = 128 - i;
        while i > 0 {
            if y & c != 0 {
                y <<= 1;
                y ^= d;
            } else {
                y <<= 1;
            }
            if x & c != 0 {
                y ^= z;
            }
            x <<= 1;
            i -= 1;
        }
        Self(y)
    }
}

fn main() {
    let x = GF::new(3u128);
    let y = GF::new(3u128);
    let GF(i) = x * y;
    println!("format {} arguments", i);
}
