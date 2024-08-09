package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"log"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	index   = flag.Uint("index", 0, "NVRAM index of read")
	useSim  = flag.Bool("simulator", false, "Use simulator instead of TPM")
)

func doStuff(ttpm transport.TPM) {

	// Create a TPM ECDH key
	tpmCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           false,
				Decrypt:              true,
				SignEncrypt:          false,
				X509Sign:             false,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDH,
						Details: NewTPMUAsymScheme(
							TPMAlgECDH,
							&TPMSKeySchemeECDH{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}
	log.Printf("Created tpmCreate %+v", tpmCreate)

	// Use NIST P-256
	curve := ecdh.P256()

	tpmCreateRsp, err := tpmCreate.Execute(ttpm)
	if err != nil {
		log.Fatalf("could not create the TPM key: %+v", err)
	}
	log.Printf("TpmCreateResponse: %+v", tpmCreateRsp)
	outPub, err := tpmCreateRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("%+v", err)
	}
	log.Printf("TPM public key: %+v", outPub)
	tpmPub, err := outPub.Unique.ECC()
	if err != nil {
		log.Fatalf("%+v", err)
	}
	log.Printf("TPM public key out: %+v", tpmPub)
	tpmPubKey, err := ECDHPubKey(curve, tpmPub)
	if err != nil {
		log.Fatalf("could not unmarshall pubkey: %+v", err)
	}
	log.Printf("TPM public key ecdh: %+v", tpmPubKey)

	// Create a SW ECDH key
	swPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("could not create the SW key: %+v", err)
	}
	log.Printf("SW key: %+v", swPriv)
	x, y, err := ECCPoint(swPriv.PublicKey())
	log.Printf("ECC x: %+v, y: %+v", x, y)
	if err != nil {
		log.Fatalf("could not get SW key point: %+v", err)
	}
	swPub := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on the SW priv * TPM pub
	zx, err := swPriv.ECDH(tpmPubKey)
	if err != nil {
		log.Fatalf("ecdh exchange: %+v", err)
	}
	log.Printf("ECC zx: %s", hex.EncodeToString(zx))

	z := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: zx},
	}

	// Calculate Z based on TPM priv * SW pub
	ecdh2 := ECDHZGen{
		KeyHandle: AuthHandle{
			Handle: tpmCreateRsp.ObjectHandle,
			Name:   tpmCreateRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InPoint: New2B(swPub),
	}
	log.Printf("ECdh2 %+v", ecdh2)
	ecdhRsp, err := ecdh2.Execute(ttpm)
	if err != nil {
		log.Fatalf("ECDH_ZGen failed: %+v", err)
	}
	log.Printf("ECDH2 execute response: %+v", ecdhRsp)

	outPoint, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		log.Fatalf("%+v", err)
	}
	log.Println()
	log.Printf("z.X: %s, outpoint.X: %s", hex.EncodeToString(z.X.Buffer), hex.EncodeToString(outPoint.X.Buffer))
	if !cmp.Equal(z.X, outPoint.X, cmpopts.IgnoreUnexported(z.X)) {
		log.Printf("want %x got %x", z, outPoint)
	}
}
func checkHW(ttpm transport.TPM) {

	// Check if EK certificate is present (often absent in simulators)
	read := NVReadPublic{NVIndex: TPMHandle(0x1c00002)} // Standard handle for EK certificate
	readResp, err := read.Execute(ttpm)
	if err != nil {
		fmt.Println("EK certificate not found. This might indicate a simulator.")
	} else {
		fmt.Println("EK certificate found. This suggests a hardware TPM.")
	}
	fmt.Printf("ReadResp: name %s, public %s \n", hex.EncodeToString(readResp.NVName.Buffer), string(readResp.NVPublic.Bytes()))

}

func main() {

	flag.Parse()

	if *useSim {
		ttpm, err := simulator.OpenSimulator()
		if err != nil {
			log.Fatalf("could not connect to TPM simulator: %+v", err)
		}
		defer ttpm.Close()
		checkHW(ttpm)
	} else {
		ttpm, err := transport.OpenTPM("/dev/tpm0")
		if err != nil {
			log.Fatalf("could not connect to TPM: %+v", err)
		}
		defer ttpm.Close()

		checkHW(ttpm)
	}

}
