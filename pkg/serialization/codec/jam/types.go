package jam

type EnumError int

type EnumType interface {
	ValueAt(index uint) (value any, err error)
	SetValue(value any) error
}
