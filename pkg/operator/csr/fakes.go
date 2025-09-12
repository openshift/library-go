package csr

type fakeKeyGenerator struct{}

func (k *fakeKeyGenerator) GenerateKeyData() ([]byte, error) {
	return []byte("fake"), nil
}

func NewFakeKeyGenerator() KeyGenerator {
	return &fakeKeyGenerator{}
}
