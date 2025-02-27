#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AndMaybe<T, U> {
    Only(T),
    Indeed(T, U),
}

impl<T, U> AndMaybe<T, U> {
    /// Get the ever-present `T` out of the structure.
    pub fn fst(&self) -> &T {
        match self {
            AndMaybe::Only(t) => t,
            AndMaybe::Indeed(t, _) => t,
        }
    }

    /// Get the `U` out of the structure, if there is one.
    pub fn snd(&self) -> Option<&U> {
        match self {
            AndMaybe::Only(_) => None,
            AndMaybe::Indeed(_, u) => Some(u),
        }
    }

    pub fn bimap<T2, U2>(&self, f: impl Fn(&T) -> T2, g: impl Fn(&U) -> U2) -> AndMaybe<T2, U2> {
        match self {
            AndMaybe::Only(t) => AndMaybe::Only(f(t)),
            AndMaybe::Indeed(t, u) => AndMaybe::Indeed(f(t), g(u)),
        }
    }
}

impl<T: Default, U> AndMaybe<T, U> {
    /// Applicative
    pub fn pure(u: U) -> Self {
        AndMaybe::Indeed(T::default(), u)
    }
}

impl<T, U> AndMaybe<T, U> {
    /// This will produce [`Indeed`] only if every element of the array is [`Indeed`], otherwise it
    /// produces an array of [`Only`] the first values.
    pub fn sequence(xs: &[Self]) -> AndMaybe<Vec<&T>, Vec<&U>> {
        let ts = xs.iter().map(|x| x.fst()).collect();

        for x in xs.iter() {
            match x {
                AndMaybe::Only(_) => return AndMaybe::Only(ts),
                AndMaybe::Indeed(_, _) => (),
            }
        }

        AndMaybe::Indeed(
            ts,
            xs.iter()
                .map(|x| x.snd().expect("the whole array is `Indeed`"))
                .collect(),
        )
    }
}
