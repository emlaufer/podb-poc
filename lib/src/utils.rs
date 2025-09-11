use pod2::middleware::{TypedValue, Value};

pub trait ToPodValue {
    fn to_pod_value(self) -> Value;
    fn to_typed_value(self) -> TypedValue;
}

impl<T: Into<TypedValue>> ToPodValue for T {
    fn to_pod_value(self) -> Value {
        Value::from(Into::<TypedValue>::into(self))
    }

    fn to_typed_value(self) -> TypedValue {
        Into::<TypedValue>::into(self)
    }
}
