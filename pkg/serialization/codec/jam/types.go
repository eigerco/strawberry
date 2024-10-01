package jam

//Keeping the same interfaces and method stubs with the scale codec to allow easy switch

type EncodeEnum interface {
	IndexValue() (index uint, value any, err error)
}

type EnumType interface {
	EncodeEnum
	ValueAt(index uint) (value any, err error)
	SetValue(value any) error
}
