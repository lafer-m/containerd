package sessions

type AuthBackend interface {
	Login() error
	Verify() error
}

type backend struct {
}

func (b *backend) Login() error {
	return nil
}

func (b *backend) Verify() error {
	return nil
}
