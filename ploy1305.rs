//please use nightly rust
#![feature(bigint_helper_methods)]
use core::arch::x86_64::_mulx_u64;
/*
新しいTLSの暗号方式ChaCha20-Poly1305 - ぼちぼち日記
https://jovi0608.hatenablog.com/entry/20160404/1459748671

must below 256-bit
p b a
y x
mul 6 times
(2^124-1)*(2^130-1) < 2^256

c++ - MSVC's instrinsics __emulu and _umul128 in GCC/CLang - Stack Overflow
https://stackoverflow.com/questions/67672215/msvcs-instrinsics-emulu-and-umul128-in-gcc-clang

Add i128 and u128 types · Issue #521 · rust-lang/rfcs · GitHub
https://github.com/rust-lang/rfcs/issues/521

core_arch::x86_64::_mulx_u64 - Rust
https://rust-lang.github.io/stdarch/x86_64/core_arch/x86_64/fn._mulx_u64.html
*/
unsafe fn mul_mod1305(a: u64, b: u64, p: u64, x: u64, y: u64) -> (u64, u64, u64) {
    let mut xa1 = 0u64;
    let mut xb1 = 0u64;
    let mut xp1 = 0u64;
    let mut ya1 = 0u64;
    let mut yb1 = 0u64;
    let mut yp1 = 0u64;
    let xa0 = _mulx_u64(x, a, &mut xa1);
    let xb0 = _mulx_u64(x, b, &mut xb1);
    let xp0 = _mulx_u64(x, p, &mut xp1);
    let ya0 = _mulx_u64(y, a, &mut ya1);
    let yb0 = _mulx_u64(y, b, &mut yb1);
    let yp0 = _mulx_u64(y, p, &mut yp1);

    let z01 = xa0;

    let (z11, c11) = xb0.overflowing_add(ya0);
    let (z12, c12) = z11.overflowing_add(xa1);

    let (z21, c21) = xb1.carrying_add(ya1, c11);
    let (z22, c22) = z21.carrying_add(yb0, c12);
    let (z23, c23) = z22.overflowing_add(xp0);

    let z31 = xp1 + yb1 + (c21 as u64) + yp0 + (c22 as u64) + (c23 as u64);

    /*
    let (z41,c41)=carrying_add(yp1,(c32 as u64),c31);
    if z41!=0u64{
    println!("{}", z41);
    }
    */

    //5=0x101
    //x*5 -> x<<2+x
    //mod 2^130 - 5 -> bottom 130-bit + (top 126-bit * 5)
    let (w01, d11) = z01.overflowing_add(z23 & 0xfffffffffffffffc);
    let (w02, d12) = w01.overflowing_add((z23 >> 2) + (z31) << 62);

    let (w11, d11) = z12.carrying_add(z31, d11);
    let (w12, d12) = w11.carrying_add(z31 >> 2, d12);

    let w21 = z23 & 3u64 + (d11 as u64) + (d12 as u64);

    //w12 overflow once at most
    let (w31, d31) = w02.overflowing_add([0u64, 5u64][((w21 >> 2) & 1) as usize]);
    return (w31, w12 + (d31 as u64), w21 & 3u64);
}

fn clamp(r0: &mut u64, r1: &mut u64) -> () {
    *r0 &= 0x0ffffffc0ffffffcu64;
    *r1 &= 0x0ffffffc0fffffffu64;
}

//Horner's rule ((0+C0)X+C1)X+…
unsafe fn poly1305update(
    z0: u64,
    z1: u64,
    z2: u64,
    bytes: [u8; 16],
    r0: u64,
    r1: u64,
) -> (u64, u64, u64) {
    const P: u64 = 2u64;
    let (x0, x1, x2) = add(z0, z1, z2, bytes, P);
    return mul_mod1305(x0, x1, x2, r0, r1);
}

fn add(x0: u64, x1: u64, x2: u64, bytes: [u8; 16], p: u64) -> (u64, u64, u64) {
    let (c0, c1) = bytes.split_at(8);
    let a = u64::from_le_bytes(c0.try_into().unwrap());
    let b = u64::from_le_bytes(c1.try_into().unwrap());
    let (mut x01, mut c01) = x0.overflowing_add(a);
    let (mut x11, mut c11) = x1.carrying_add(b, c01);
    let mut x21 = x2 + p + (c11 as u64);

    (x01, c01) = x01.overflowing_add([0u64, 5u64][((x21 >> 2) & 1) as usize]);
    (x11, c11) = x11.overflowing_add(c01 as u64);
    x21 &= 3u64;
    x21 += c11 as u64;

    return (x01, x11, x21);
}

fn poly(v: &[u8], key: &[u8]) -> (u64, u64) {
    let mut ki = key.rchunks_exact(8);

    let mut r0 = u64::from_le_bytes(ki.next().unwrap().try_into().unwrap());
    let mut r1 = u64::from_le_bytes(ki.next().unwrap().try_into().unwrap());
    clamp(&mut r0, &mut r1);
    let s0 = u64::from_le_bytes(ki.next().unwrap().try_into().unwrap());
    let s1 = u64::from_le_bytes(ki.next().unwrap().try_into().unwrap());

    let (mut x0, mut x1, mut x2) = (0u64, 0u64, 0u64);
    let mut it = v.rchunks_exact(16);
    unsafe {
        while let Some(chunk) = it.next() {
            (x0, x1, x2) = poly1305update(x0, x1, x2, chunk.try_into().unwrap(), r0, r1);
        }
        let v0 = it.remainder();
        let vx = v0.len();
        let mut vf: [u8; 16] = [0; 16];
        //let vf=[v0,&[2u8],&values].concat();
        vf[..vx].copy_from_slice(&v0);
        vf[vx] = 2u8;
        (x0, x1, x2) = add(x0, x1, x2, vf, 0u64);
        (x0, x1, _) = mul_mod1305(x0, x1, x2, r0, r1);
    }

    let (x01, c01) = x0.overflowing_add(s0);
    let x02 = x1 + s1 + c01 as u64;

    return (x01, x02);
}

fn main() {
    let mut x = 1u64;
    let mut y = 0u64;
    clamp(&mut x, &mut y);

    let v = [1u8; 90];
    let (x0, x1) = poly(&v, &[1u8; 64]);
    println!("{} {}", x0, x1);
}
