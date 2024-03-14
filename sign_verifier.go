package thirdwebauth

type Signer interface {
	SignMessage(message string) (string, error)
}

type Verifier interface {
	VerifySignature(message, signature string) (bool, error)
}

type SignVerifier interface {
	Signer
	Verifier
}
