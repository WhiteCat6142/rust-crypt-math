//https://docs.rs/num-bigint/latest/num_bigint/
/*
フェルマーの小定理 - Wikipedia
https://ja.wikipedia.org/wiki/%E3%83%95%E3%82%A7%E3%83%AB%E3%83%9E%E3%83%BC%E3%81%AE%E5%B0%8F%E5%AE%9A%E7%90%86
*/
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_traits::cast::ToPrimitive;

/*
Miller–Rabin
ミラー–ラビン素数判定法 - Wikipedia
https://ja.wikipedia.org/wiki/%E3%83%9F%E3%83%A9%E3%83%BC%E2%80%93%E3%83%A9%E3%83%93%E3%83%B3%E7%B4%A0%E6%95%B0%E5%88%A4%E5%AE%9A%E6%B3%95
*/
fn prime(n: &BigUint) -> bool {
    let n0 = n.to_u64();
    if n0.is_some() {
        let n00 = n0.unwrap();
        if n00 - 2 == 0 {
            return true;
        }
        if n00 == 1 || n00 & 1 == 0 {
            return false;
        }
    }
    let mut rng = rand::thread_rng();
    let d0: BigUint = n.clone() - 1u64;
    // must be s>0 because n is odd
    let s: u64 = d0.trailing_zeros().unwrap();
    let d: BigUint = d0.clone() >> s;
    let zero = BigUint::from(0u64);
    let one = BigUint::from(1u64);
    for _ in 0..190 {
        let a = rng.gen_biguint_below(&d0);
        if a==zero{
            continue;
        }
        let mut y = a.clone().modpow(&d, &n);
        let mut i = s;
        if y == one {
            continue;
        }
        while y != d0 {
            if i == 0 {
                return false;
            }
            y = y.modpow(&y, &n);
            i -= 1;
        }
    }
    return true;
}

/*
Rustのconst fnの制限がさらに緩和された(Rust 1.46.0) - Qiita
https://qiita.com/block/items/de9ecbb4d102eaa35ac8
*/

const fn gcd_extended(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (gcd, x1, y1) = gcd_extended(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    return (gcd, x, y);
}

fn main() {
    const A :i64= 35;
    const B :i64=15;
    const X :(i64, i64, i64)= gcd_extended(A, B);
    let (g, x, y) = X;
    let t = prime(&BigUint::from(101u64));
    let (v, w) = gen_key(24);
    let m = decrypt(encrypt(BigUint::from(30531u64), &v, 65537u64), &w, &v);
    println!("gcd({},{}) = {}, {}, {}", A, B, g, x, y);  
    println!("101 is prime: {}", t);
    println!("message {}", m);
    println!("{},{}", v, w);
}

/*
RSA Algorithm
https://www.di-mgt.com.au/rsa_alg.html
*/

fn gen_prime(k: u64) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut p = rng.gen_biguint(k);
    p.set_bit(0, true);
    p.set_bit(k - 1, true);
    loop {
        if prime(&p) {
            return p;
        }
        p += 2u64;
    }
}
fn gen_keyprime(k: u64, e: u64) -> BigUint {
    loop {
        let p = gen_prime(k);
        if (p.clone() % e).to_u64().unwrap() != 1 {
            return p;
        }
    }
}

fn gen_key(k: u64) -> (BigUint, BigUint) {
    let e = 65537u64;
    let p = gen_keyprime(k, e);
    let q = gen_keyprime(k, e);
    let n = p.clone() * q.clone();
    let l = (p - 1u64) * (q - 1u64);
    let (gcd, x, y) = gcd_extended((l.clone() % e).to_i64().unwrap(), 65537);
    if gcd != 1 {
        return gen_key(k);
    }
    let d = if x > 0 {
        l.clone() - (l / e) * (x as u64) - ((-y) as u64)
    } else {
        (l / e) * ((-x) as u64) + (y as u64)
    };
    return (n, d);
}

/*
From Fermat's little theorem
a^(p-1)=1 mod p

Choose d
de=(p-1)(q-1)l+1

Now
a^(p-1)(q-1)l=1 mod p
a^(p-1)(q-1)l=1 mod q
p,q:primes & gcd(p,q)=1
Then
a^(p-1)(q-1)l=1 mod pq

It means
a^de=a mod pq
*/

fn encrypt(m: BigUint, n: &BigUint, e: u64) -> BigUint {
    m.modpow(&BigUint::from(e), &n)
}
fn decrypt(c: BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    c.modpow(&d, &n)
}
