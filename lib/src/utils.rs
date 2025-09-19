use pod2::backends::plonky2::signer::Signer;
use pod2::frontend::{SignedDict, SignedDictBuilder};
use pod2::middleware::{Params, RawValue, TypedValue, Value, containers::Dictionary};

pub trait ToPodValue {
    fn to_pod_value(self) -> Value;
    fn to_typed_value(self) -> TypedValue;
    fn to_raw_value(self) -> RawValue;
}

impl<T: Into<TypedValue>> ToPodValue for T {
    fn to_pod_value(self) -> Value {
        Value::from(Into::<TypedValue>::into(self))
    }

    fn to_typed_value(self) -> TypedValue {
        Into::<TypedValue>::into(self)
    }

    fn to_raw_value(self) -> RawValue {
        self.to_pod_value().raw()
    }
}
