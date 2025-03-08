#[macro_export]
macro_rules! create_and_reexport {
    ($($name: ident),+ $(,)?) => {
        $(
            mod $name;
            #[allow(unused_imports)]
            pub use $name::*;
        )+
    };
}
