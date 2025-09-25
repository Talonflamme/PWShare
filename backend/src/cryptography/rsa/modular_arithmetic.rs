use num_bigint::BigUint;

pub trait ModularArithmetic {
    type Output;

    fn addm(self, rhs: Self, m: Self) -> Self::Output;
    fn subm(self, rhs: Self, m: Self) -> Self::Output;
    fn mulm(self, rhs: Self, m: Self) -> Self::Output;
}

impl ModularArithmetic for &BigUint {
    type Output = BigUint;

    fn addm(self, rhs: Self, m: Self) -> Self::Output {
        (self + rhs) % m
    }

    fn subm(self, rhs: Self, m: Self) -> Self::Output {
        let lhs = self % m;
        let rhs = rhs % m;
        if lhs >= rhs {
            lhs - rhs
        } else {
            m - (rhs - lhs)
        }
    }

    fn mulm(self, rhs: Self, m: Self) -> Self::Output {
        (self * rhs) % m
    }
}
