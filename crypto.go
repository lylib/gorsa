package gorsa

import (
	"bytes"
	"crypto"
	"errors"
	"io/ioutil"
)

//公钥签名
func (rsas *RSASecurity) PublicKeySign(dataToVerify []byte, hash crypto.Hash) ([]byte, error) {
	if rsas.pubkey == nil {
		return []byte(""), errors.New(`Please set the public key in advance`)
	}
	//hash data
	hashHandler := hash.New()
	hashHandler.Write(dataToVerify)
	hashedData := hashHandler.Sum(nil)

	//encrypt hash data
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(rsas.pubkey, bytes.NewReader(hashedData), output, true)
	if err != nil {
		return []byte(""), err
	}

	//return signature
	return ioutil.ReadAll(output)
}

//私钥验证
func (rsas *RSASecurity) PrivateKeyVerify(dataToVerify, signature []byte, hash crypto.Hash) (bool, error) {
	if rsas.prikey == nil {
		return false, errors.New(`Please set the private key in advance`)
	}
	//hash data
	hashHandler := hash.New()
	hashHandler.Write(dataToVerify)
	hashedData := hashHandler.Sum(nil)

	//decrypt signature
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(signature), output, false)
	if err != nil {
		return false, err
	}
	signatureDecryptData, err := ioutil.ReadAll(output)
	if err != nil {
		return false, err
	}

	//compare hash data
	for s_num, s_value := range signatureDecryptData {
		if hashedData[s_num] != s_value {
			return false, errors.New("compare fail")
		}
	}
	return true, nil
}

//私钥签名
func (rsas *RSASecurity) PrivateKeySign(dataToVerify []byte, hash crypto.Hash) ([]byte, error) {
	if rsas.prikey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	//hash data
	hashHandler := hash.New()
	hashHandler.Write(dataToVerify)
	hashedData := hashHandler.Sum(nil)

	//encrypt hash data
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(hashedData), output, true)
	if err != nil {
		return []byte(""), err
	}

	//return signature
	return ioutil.ReadAll(output)
}

//公钥验证
func (rsas *RSASecurity) PublicKeyVerify(dataToVerify, signature []byte, hash crypto.Hash) (bool, error) {
	if rsas.pubkey == nil {
		return false, errors.New(`Please set the public key in advance`)
	}
	//hash data
	hashHandler := hash.New()
	hashHandler.Write(dataToVerify)
	hashedData := hashHandler.Sum(nil)

	//decrypt signature
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(rsas.pubkey, bytes.NewReader(signature), output, false)
	if err != nil {
		return false, err
	}
	signatureDecryptData, err := ioutil.ReadAll(output)
	if err != nil {
		return false, err
	}

	//compare hash data
	for s_num, s_value := range signatureDecryptData {
		if hashedData[s_num] != s_value {
			return false, errors.New("compare fail")
		}
	}
	return true, nil
}
