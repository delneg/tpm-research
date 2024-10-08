## Tpm research


Here I collect my finding for TPM

## Specs

https://trustedcomputinggroup.org/resource/tpm-library-specification/

## Usage guideline

https://trustedcomputinggroup.org/resource/how-to-use-the-tpm-a-guide-to-hardware-based-endpoint-security/#:~:text=1%20Set%20password%202%20Store%20digital%20credentials%20such,hard%20drive%20shutdown%20for%20endpoint%20integrity%20More%20items

https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-recommendations

## Docs

https://trustedcomputinggroup.org/wp-content/uploads/TCG_-CPU_-TPM_Bus_Protection_Guidance_Active_Attack_Mitigations-V1-R30_PUB-1.pdf

https://trustedcomputinggroup.org/wp-content/uploads/Registry-of-Reserved-TPM-2.0-Handles-and-Localities-Version-1.2-Revision-1.00_pub.pdf

https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.06-Revision-0.94_pub.pdf

https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf


https://www.nuvoton.com/export/sites/nuvoton/files/security/Nuvoton_TPM_EK_Certificate_Chain_Rev2.1.pdf

https://trustedcomputinggroup.org/resource/tpm-library-specification/

## Papers

https://is.muni.cz/th/bplt1/thesis.pdf - Systematic collection of TPM 2.0 chips attributes on Linux

## Courses

https://github.com/nokia/TPMCourse/blob/master/docs/keys.md

https://github.com/Abhinandan-Khurana/Learn-TPM

## Certs

https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202112.cer

## Dotnet

https://github.com/Lumoin/Verifiable/blob/main/documents/ADRs/tpm-and-hardware-security.md

https://github.com/Lumoin/Verifiable/blob/main/src/Verifiable.Tpm/Verifiable.Tpm.csproj

## Flakebox

https://github.com/rustshop/flakebox/blob/master/docs/building-new-project.md

## Google tpm

https://github.com/google/go-tpm/blob/main/examples/tpm-genaik/genaik.go

https://github.com/Foxboron/go-tpm-keyfiles


## Usecases


https://github.com/salrashid123/golang-jwt-tpm

https://github.com/salrashid123/golang-jwt-tpm

https://github.com/salrashid123/golang-jwt-pkcs11

https://github.com/salrashid123/signer

https://github.com/salrashid123/go_tpm_https_embed

https://github.com/salrashid123/tpmrand

https://github.com/salrashid123/tls_ak

https://github.com/salrashid123/aws_hmac

https://github.com/salrashid123/go-tpm-wrapping

## Raspi

https://community.element14.com/products/roadtest/rv/roadtest_reviews/1514/infineon_trust_platf

https://www.infineon.com/dgdl/Infineon-TPM20_Embedded_RPi_TSS_SLx_9670_AppNote-ApplicationNotes-v01_01-EN.zip?fileId=5546d4626eab8fbf016f13f1c3ff4c50&redirId=117198



## Remote attestation


```
2.2.1.4 Low Range
The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
0x01c00002 RSA 2048 EK Certificate
0x01c00003 RSA 2048 EK Nonce
0x01c00004 RSA 2048 EK Template
0x01c0000a ECC NIST P256 EK Certificate
0x01c0000b ECC NIST P256 EK Nonce
0x01c0000c ECC NIST P256 EK Template
```

https://github.com/salrashid123/go_tpm_remote_attestation

https://github.com/SecJoe/TPM-Remote-Attestation-using-Intel-SGX

https://github.com/ANSSI-FR/ultrablue

https://github.com/Infineon/remote-attestation-optiga-tpm/blob/master/documents/tpm-appnote-ra.pdf

https://github.com/Infineon/remote-attestation-optiga-tpm/blob/server/server/src/main/java/com/ifx/server/tss/TPMEngine.java

## Ecdh

https://github.com/google/go-tpm/blob/main/tpm2/test/ecdh_test.go

https://linderud.dev/blog/golang-crypto/ecdh-and-the-tpm/



## Apple

https://duo.com/labs/research/apple-t2-xpc

https://github.com/remko/age-plugin-se/blob/main/Sources/Plugin.swift

https://github.com/google/go-tpm/issues/286

https://github.com/Foxboron/swtpm_test/issues/1

## IMA (Integrity Measurement Architecture)

https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture

https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy

https://sourceforge.net/p/linux-ima/wiki/Home/

https://ima-doc.readthedocs.io/en/latest/ima-configuration.html

