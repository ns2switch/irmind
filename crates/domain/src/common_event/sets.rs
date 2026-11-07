use super::{EventCategory, EventSchemaError, EventType};
macro_rules! set {
    ($name:ident,$item:ident,$all:literal) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        pub struct $name(u32);
        impl $name {
            pub fn from_bits(bits: u32) -> Result<Self, EventSchemaError> {
                if bits & !$all != 0 {
                    return Err(EventSchemaError::UnknownCode);
                }
                Ok(Self(bits))
            }
            pub fn new(items: impl IntoIterator<Item = $item>) -> Self {
                Self(
                    items
                        .into_iter()
                        .fold(0, |bits, v| bits | (1u32 << v.code())),
                )
            }
            pub const fn bits(self) -> u32 {
                self.0
            }
            pub fn contains(self, item: $item) -> bool {
                self.0 & (1u32 << item.code()) != 0
            }
            pub fn iter(self) -> impl Iterator<Item = $item> {
                (0u16..32)
                    .filter_map(|code| $item::from_code(code).ok())
                    .filter(move |v| self.contains(*v))
            }
        }
    };
}
set!(CategorySet, EventCategory, 0x000f_ffffu32);
set!(EventTypeSet, EventType, 0x0003_ffffu32);
