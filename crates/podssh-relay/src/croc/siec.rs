//! SIEC255, the curve of croc's relay handshake (tscholl2/siec:siec.go at
//! `c2c6f6198406`, which schollz/pake v3 names `siec`): y² = x³ + 19 over a
//! prime field of 255 bits, of prime order, with the base point (5, 12). No
//! Rust crate implements it, so it is here, on num-bigint's integers.
//!
//! The point at infinity is (0, 0), as siec.go writes it, which is not on the
//! curve. Each sum and multiple is the group's, as siec.go's `Add`, `Double`
//! and `ScalarMult` give them; the work is done in Jacobian coordinates, with
//! one inversion at the end, as a scalar multiple with an inversion at each
//! step takes seconds in a debug build. Not constant time: the relay's
//! handshake keys a public password with a public weak key (`super::pake`),
//! so a timing tells nothing that is not public.

use num_bigint::BigUint;

/// The field's prime, the group's order and the points of schollz/pake v3's
/// `initCurve("siec")` (pake.go at v3.2.0), in decimal as the sources write
/// them.
const P: &[u8] = b"28948022309329048855892746252183396360603931420023084536990047309120118726721";
const N: &[u8] = b"28948022309329048855892746252183396360263649053102146073526672701688283398081";
const UX: &[u8] = b"793136080485469241208656611513609866400481671853";
const UY: &[u8] = b"18458907634222644275952014841865282643645472623913459400556233196838128612339";
const VX: &[u8] = b"1086685267857089638167386722555472967068468061489";
const VY: &[u8] = b"19593504966619549205903364028255899745298716108914514072669075231742699650911";

/// A point in affine coordinates; (0, 0) is the point at infinity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

impl Point {
    pub fn infinity() -> Point {
        Point { x: BigUint::default(), y: BigUint::default() }
    }

    pub fn is_infinity(&self) -> bool {
        self.x.bits() == 0 && self.y.bits() == 0
    }
}

/// A point in Jacobian coordinates: (X / Z², Y / Z³); Z = 0 at infinity.
#[derive(Clone)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

/// The curve, its constants read once for a handshake.
pub struct Curve {
    p: BigUint,
    n: BigUint,
    pub g: Point,
    /// pake's two fixed masking points.
    pub u: Point,
    pub v: Point,
}

fn decimal(text: &[u8]) -> BigUint {
    // The constants above are decimal digits: each parses.
    BigUint::parse_bytes(text, 10).unwrap_or_default()
}

impl Curve {
    pub fn siec() -> Curve {
        Curve {
            p: decimal(P),
            n: decimal(N),
            g: Point { x: BigUint::from(5u32), y: BigUint::from(12u32) },
            u: Point { x: decimal(UX), y: decimal(UY) },
            v: Point { x: decimal(VX), y: decimal(VY) },
        }
    }

    /// The field's prime.
    pub fn prime(&self) -> &BigUint {
        &self.p
    }

    /// Whether (x, y), each below the prime, is on the curve; the point at
    /// infinity is not, as siec.go's `IsOnCurve` answers.
    pub fn is_on_curve(&self, point: &Point) -> bool {
        if point.x >= self.p || point.y >= self.p {
            return false;
        }
        let left = self.mul(&point.y, &point.y);
        let right = (self.mul(&self.mul(&point.x, &point.x), &point.x) + BigUint::from(19u32)) % &self.p;
        left == right
    }

    /// `point` negated: (x, p − y).
    pub fn negate(&self, point: &Point) -> Point {
        if point.is_infinity() {
            return point.clone();
        }
        Point { x: point.x.clone(), y: self.sub(&BigUint::default(), &point.y) }
    }

    /// The sum of two points.
    pub fn add(&self, a: &Point, b: &Point) -> Point {
        self.affine(&self.jadd(&self.jacobian(a), &self.jacobian(b)))
    }

    /// `k` times `point`, `k` read as a big-endian number, as siec.go's
    /// `ScalarMult` reads it; the multiple of `k` modulo the group's order is
    /// the same point, and fewer steps.
    pub fn multiply(&self, point: &Point, k: &[u8]) -> Point {
        let k = BigUint::from_bytes_be(k) % &self.n;
        let base = self.jacobian(point);
        let mut acc = self.jacobian(&Point::infinity());
        for i in (0..k.bits()).rev() {
            acc = self.jdouble(&acc);
            if k.bit(i) {
                acc = self.jadd(&acc, &base);
            }
        }
        self.affine(&acc)
    }

    /// a − b modulo the prime, each below it.
    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        ((a + &self.p) - b) % &self.p
    }

    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }

    fn small(&self, k: u32, a: &BigUint) -> BigUint {
        (a * BigUint::from(k)) % &self.p
    }

    fn jacobian(&self, point: &Point) -> Jacobian {
        if point.is_infinity() {
            return Jacobian { x: BigUint::from(1u32), y: BigUint::from(1u32), z: BigUint::default() };
        }
        Jacobian { x: point.x.clone() % &self.p, y: point.y.clone() % &self.p, z: BigUint::from(1u32) }
    }

    fn affine(&self, j: &Jacobian) -> Point {
        if j.z.bits() == 0 {
            return Point::infinity();
        }
        // The prime's Fermat inverse: z^(p−2).
        let inverse = j.z.modpow(&(&self.p - BigUint::from(2u32)), &self.p);
        let inverse2 = self.mul(&inverse, &inverse);
        let inverse3 = self.mul(&inverse2, &inverse);
        Point { x: self.mul(&j.x, &inverse2), y: self.mul(&j.y, &inverse3) }
    }

    /// 2P for a = 0: S = 4XY², M = 3X², X' = M² − 2S, Y' = M(S − X') − 8Y⁴,
    /// Z' = 2YZ.
    fn jdouble(&self, j: &Jacobian) -> Jacobian {
        if j.z.bits() == 0 || j.y.bits() == 0 {
            return self.jacobian(&Point::infinity());
        }
        let yy = self.mul(&j.y, &j.y);
        let s = self.small(4, &self.mul(&j.x, &yy));
        let m = self.small(3, &self.mul(&j.x, &j.x));
        let x = self.sub(&self.mul(&m, &m), &self.small(2, &s));
        let y = self.sub(&self.mul(&m, &self.sub(&s, &x)), &self.small(8, &self.mul(&yy, &yy)));
        let z = self.small(2, &self.mul(&j.y, &j.z));
        Jacobian { x, y, z }
    }

    /// P + Q: U1 = X1·Z2², U2 = X2·Z1², S1 = Y1·Z2³, S2 = Y2·Z1³, H = U2 − U1,
    /// R = S2 − S1; X' = R² − H³ − 2·U1·H², Y' = R(U1·H² − X') − S1·H³,
    /// Z' = H·Z1·Z2. Equal points double; opposite ones give infinity.
    fn jadd(&self, a: &Jacobian, b: &Jacobian) -> Jacobian {
        if a.z.bits() == 0 {
            return b.clone();
        }
        if b.z.bits() == 0 {
            return a.clone();
        }
        let (z1z1, z2z2) = (self.mul(&a.z, &a.z), self.mul(&b.z, &b.z));
        let u1 = self.mul(&a.x, &z2z2);
        let u2 = self.mul(&b.x, &z1z1);
        let s1 = self.mul(&a.y, &self.mul(&b.z, &z2z2));
        let s2 = self.mul(&b.y, &self.mul(&a.z, &z1z1));
        let h = self.sub(&u2, &u1);
        let r = self.sub(&s2, &s1);
        if h.bits() == 0 {
            return if r.bits() == 0 { self.jdouble(a) } else { self.jacobian(&Point::infinity()) };
        }
        let hh = self.mul(&h, &h);
        let hhh = self.mul(&hh, &h);
        let u1hh = self.mul(&u1, &hh);
        let x = self.sub(&self.sub(&self.mul(&r, &r), &hhh), &self.small(2, &u1hh));
        let y = self.sub(&self.mul(&r, &self.sub(&u1hh, &x)), &self.mul(&s1, &hhh));
        let z = self.mul(&h, &self.mul(&a.z, &b.z));
        Jacobian { x, y, z }
    }
}

/// The bytes of a coordinate as Go's `big.Int.Bytes` gives them: big-endian,
/// no leading zero, and none at all for zero.
pub fn go_bytes(n: &BigUint) -> Vec<u8> {
    if n.bits() == 0 {
        Vec::new()
    } else {
        n.to_bytes_be()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(x: &str, y: &str) -> Point {
        Point { x: decimal(x.as_bytes()), y: decimal(y.as_bytes()) }
    }

    // Computed with a Python transcription of siec.go's affine `Add`,
    // `Double` and `ScalarMult` (one inversion at each step), which shares
    // no code with this file's Jacobian forms.
    #[test]
    fn multiples_of_the_base_point_are_siec_go_s() {
        let curve = Curve::siec();
        let two = point(
            "6784692728748995825599862402855483522016546426567910438357042338075027826575",
            "14982863109320699114866362806305859444453206692004135551371801829915686450358",
        );
        assert_eq!(curve.multiply(&curve.g, &[2]), two);
        assert_eq!(curve.add(&curve.g, &curve.g), two);
        let g0102 = point(
            "11942350755365550915679680751581907201010311994416446345917144212573158574544",
            "5172175651221548419663802116812104929080211418462877121449376793219517849997",
        );
        assert_eq!(curve.multiply(&curve.g, &[1, 2]), g0102);
        let upw = point(
            "22956937362418003810795788298277477520112122942221430030045684546288141940319",
            "16642281345375569801081907338623917718137167350786177661562925824178884381367",
        );
        assert_eq!(curve.multiply(&curve.u, &[1, 2, 3]), upw);
    }

    #[test]
    fn the_points_of_pake_are_on_the_curve_and_infinity_is_not() {
        let curve = Curve::siec();
        for p in [&curve.g, &curve.u, &curve.v] {
            assert!(curve.is_on_curve(p), "{p:?}");
        }
        assert!(!curve.is_on_curve(&Point::infinity()));
        let off = Point { x: BigUint::from(5u32), y: BigUint::from(13u32) };
        assert!(!curve.is_on_curve(&off));
        // A coordinate at or past the prime is refused, as the web client does.
        let past = Point { x: &curve.g.x + curve.prime(), y: curve.g.y.clone() };
        assert!(!curve.is_on_curve(&past));
    }

    #[test]
    fn a_point_and_its_negation_sum_to_infinity_and_the_order_kills_each_point() {
        let curve = Curve::siec();
        let p = curve.multiply(&curve.g, &[7, 7, 7]);
        assert!(curve.add(&p, &curve.negate(&p)).is_infinity());
        assert_eq!(curve.add(&p, &Point::infinity()), p);
        let order = curve.n.to_bytes_be();
        assert!(curve.multiply(&curve.g, &order).is_infinity());
        // A scalar past the order is its remainder, as siec.go's bit by bit
        // multiple gives the same point.
        let big = [0xffu8; 32];
        let rest = (BigUint::from_bytes_be(&big) % &curve.n).to_bytes_be();
        assert_eq!(curve.multiply(&curve.g, &big), curve.multiply(&curve.g, &rest));
        assert!(go_bytes(&BigUint::default()).is_empty());
        assert_eq!(go_bytes(&BigUint::from(258u32)), vec![1, 2]);
    }
}
