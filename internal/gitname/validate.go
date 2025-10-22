package gitname

func Validate(name string) error {
	_, err := Parse(name)
	return err
}
