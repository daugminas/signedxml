package signedxml

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/beevik/etree"
)

/*
Inserts an XML document into the XML template - both inputs in the form of a string. Returns a
XML string document prepared for signing. No transforms are done.

Returns error, if something goes wrong. Typically, a missing <Signature> or <Object> tag in the template..
or Object "Id" attribute missing.

Params:
xmlSignatureTemplate - the template to be used, i.e. where the document is inserted into;
xmlToBeInserted - the XML document to be inserted into the template
unindent - unindent/minify resulting document;
addProcessInstructions - add processing instructions for at the header of the XML, i.e. `version="1.0" encoding="UTF-8"`
*/
func InsertXMLintoSignatureTemplate(xmlSignatureTemplate string, xmlToBeInserted string, unindent bool, addProcessInstructions bool) (out string, e error) {

	// grazinti tuscia stringa, jei nera inputo
	if xmlSignatureTemplate == "" || xmlToBeInserted == "" {
		return
	}

	// parsinam template
	sigDoc := etree.NewDocument()
	if addProcessInstructions {
		sigDoc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	}
	e = sigDoc.ReadFromString(xmlSignatureTemplate)
	if e != nil {
		return
	}
	sig := sigDoc.Root()
	if sig == nil || sig.Tag != "Signature" {
		// log.Fatal("no root tag present in signatureXML or its root tag is not `Signature`")
		return "", errors.New("no root tag present in xmlSignatureTemplate or its root tag is not `Signature`")
	}
	obj := sig.FindElement(".//Object")
	if obj == nil {
		return "", errors.New("no 'Object' tag found in xmlSignatureTemplate, can't insert xmlToBeInserted")
	}

	// parsinam xmlToBeInserted
	sigTargetDoc := etree.NewDocument()
	e = sigTargetDoc.ReadFromString(xmlToBeInserted)
	if e != nil {
		return
	}
	sigTarget := sigTargetDoc.Root()
	if sigTarget == nil {
		return "", errors.New("can't set root of the 'xmlToBeInserted' document")
	}

	// kabinam
	obj.AddChild(sigTarget)
	if unindent {
		sigDoc.Unindent()
	}

	return sigDoc.WriteToString()
}

func InsertTextIntoSignatureTemplate(xmlSignatureTemplate string, text string, unindent bool, addProcessInstructions bool) (out string, e error) {

	// grazinti tuscia stringa, jei nera inputo
	if xmlSignatureTemplate == "" || text == "" {
		return
	}

	// parsinam template
	sigDoc := etree.NewDocument()
	if addProcessInstructions {
		sigDoc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	}
	e = sigDoc.ReadFromString(xmlSignatureTemplate)
	if e != nil {
		return
	}
	sig := sigDoc.Root()
	if sig == nil || sig.Tag != "Signature" {
		return "", errors.New("no root tag present in xmlSignatureTemplate or its root tag is not `Signature`")
	}
	obj := sig.FindElement(".//Object")
	if obj == nil {
		return "", errors.New("no 'Object' tag found in xmlSignatureTemplate, can't insert xmlToBeInserted")
	}

	// kabinam texta
	obj.SetText(text)

	if unindent {
		sigDoc.Unindent()
	}

	return sigDoc.WriteToString()
}

/*
Decodes private key bytes in the PEM format and parses it into PKCS #8, ASN.1 DER form, which
then can be used by signer.Sign(key)
*/
func PrepPKCS8PrivateKey(PEMKeyBytes []byte) (key any, e error) {
	if PEMKeyBytes == nil {
		return nil, errors.New("no private key bytes provided")
	}
	pemBlock, _ := pem.Decode(PEMKeyBytes)
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}
