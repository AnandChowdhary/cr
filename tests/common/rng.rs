//! The one pseudo-random generator every property test shares, and the one way
//! a failure is reported and replayed.
//!
//! ## Why there is no property-testing dependency
//!
//! A generator crate would buy shrinking and a nicer failure report. It would
//! also change `Cargo.lock`, which needs an MSRV check, and none of the
//! generation these suites need is something a combinator library makes
//! materially better: a weighted choice among a few operations, a string built
//! from a pool of awkward fragments, a YAML value a few levels deep. Shrinking
//! buys little against a fixed seed set whose cases are small to begin with.
//! What matters more is that a green run in CI means the same thing as a green
//! run on a laptop, and that a red one can be replayed exactly.
//!
//! ## Reproducing a failure
//!
//! Each property runs once per seed, from `0` up to its default case count, so
//! every run explores exactly the same inputs. When a case panics, [`Case`]
//! prints the property's name and the seed before the panic reaches the test
//! harness:
//!
//! ```text
//! property 'filters_agree_with_a_reference_evaluator' failed for seed 17;
//! replay it with CR_PROPERTY_SEED=17 cargo test filters_agree_with_a_reference_evaluator
//! ```
//!
//! `CR_PROPERTY_SEED=<n>` runs seed `n` alone, and `CR_PROPERTY_SCALE=<k>` runs
//! `k` times the default number of seeds, for a longer local search than CI can
//! afford. A seed found at any scale replays at the default one, because a seed
//! names the inputs and nothing else.
//!
//! The generator itself is SplitMix64: deterministic, tiny, and identical on
//! every platform. Its first outputs are pinned by
//! `tests/audit_properties.rs::the_generator_is_reproducible`, so "the same
//! seed" cannot silently change meaning between releases.
//!
//! This file has no dependencies beyond `std`, because it is compiled twice:
//! once as `tests/common/rng.rs` for the integration tests, and once into the
//! library's own unit tests by `src/frontmatter/properties.rs`, which exercises
//! a parser that is not public.

#![allow(dead_code)]

/// Replays one seed of every property that runs.
pub const SEED_VARIABLE: &str = "CR_PROPERTY_SEED";
/// Multiplies every property's default number of seeds.
pub const SCALE_VARIABLE: &str = "CR_PROPERTY_SCALE";

/// SplitMix64.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// A number in `0..bound`. `bound` must not be zero.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    /// A number in `low..=high`.
    pub fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high - low + 1)
    }

    /// True `numerator` times in `denominator`.
    pub fn chance(&mut self, numerator: usize, denominator: usize) -> bool {
        self.below(denominator) < numerator
    }

    /// One item of a non-empty slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Shuffle `items` in place (Fisher–Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            items.swap(index, self.below(index + 1));
        }
    }
}

/// One run of a property: its seed, its generator, and the report that names
/// both if the run panics.
#[derive(Debug)]
pub struct Case {
    pub seed: u64,
    pub rng: Rng,
    property: &'static str,
}

impl Drop for Case {
    fn drop(&mut self) {
        // A case is dropped while unwinding when its property failed, which is
        // the one moment the seed is worth printing. This works for `async`
        // tests too, where a `catch_unwind` around the body would need a
        // future combinator the crate does not depend on.
        if std::thread::panicking() {
            eprintln!(
                "property '{name}' failed for seed {seed}; replay it with {SEED_VARIABLE}={seed} cargo test {name}",
                name = self.property,
                seed = self.seed,
            );
        }
    }
}

/// The cases of `property`: seeds `0..default_cases` scaled by
/// [`SCALE_VARIABLE`], or the one seed [`SEED_VARIABLE`] names.
///
/// Iterate with `for mut case in cases(...)` and keep the case alive for the
/// whole iteration, so a panic anywhere in it reports the seed.
pub fn cases(property: &'static str, default_cases: u64) -> impl Iterator<Item = Case> {
    let seeds = match environment_number(SEED_VARIABLE) {
        Some(seed) => seed..seed + 1,
        None => 0..default_cases * environment_number(SCALE_VARIABLE).unwrap_or(1).max(1),
    };
    seeds.map(move |seed| Case {
        seed,
        rng: Rng::new(seed),
        property,
    })
}

fn environment_number(name: &str) -> Option<u64> {
    let value = std::env::var(name).ok()?;
    Some(
        value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a non-negative integer, not {value:?}")),
    )
}
