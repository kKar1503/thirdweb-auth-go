package utils

import (
	"bytes"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const EthereumMessagePrefix = "\x19Ethereum Signed Message:\n"

func VerifySignature(
	message, signature, address string,
	clientID, secretKey string,
) (bool, error) {
	messageHash := HashMessage([]byte(message))
	recoveredAddress, err := crypto.Ecrecover(messageHash.Bytes(), []byte(signature))
	if err != nil {
		return false, err
	}

	return bytes.Equal(recoveredAddress, common.HexToAddress(address).Bytes()), nil
}

func HashMessage(message []byte) common.Hash {
	return crypto.Keccak256Hash([]byte(EthereumMessagePrefix), []byte(strconv.Itoa(len(message))), message)
}
