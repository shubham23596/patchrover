package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shubham23596/patchrover/internal/model"
	"github.com/shubham23596/patchrover/internal/pack"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pack-sign:", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("pack-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packPath := flags.String("pack", "", "response-pack JSON file or directory")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return errors.New("usage: pack-sign --pack <file-or-directory> < base64-ed25519-seed")
	}
	if *packPath == "" || flags.NArg() != 0 {
		return errors.New("usage: pack-sign --pack <file-or-directory> < base64-ed25519-seed")
	}

	encodedSeed, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return fmt.Errorf("read signing seed: %w", err)
	}
	if len(encodedSeed) > 4096 {
		return errors.New("signing seed input exceeds safety limit")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedSeed)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("stdin must contain exactly one base64-encoded Ed25519 seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	for index := range seed {
		seed[index] = 0
	}
	defer func() {
		for index := range privateKey {
			privateKey[index] = 0
		}
	}()

	path, err := resolvePackPath(*packPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read response pack: %w", err)
	}
	responsePack, err := decodePack(data)
	if err != nil {
		return err
	}
	responsePack, err = pack.Sign(responsePack, privateKey)
	if err != nil {
		return fmt.Errorf("sign response pack: %w", err)
	}
	validation, err := pack.Validate(responsePack, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("validate signed response pack: %w", err)
	}
	if err := pack.RequireTrusted(validation); err != nil {
		return err
	}

	formatted, err := json.MarshalIndent(responsePack, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed response pack: %w", err)
	}
	formatted = append(formatted, '\n')
	if err := atomicWrite(path, formatted); err != nil {
		return err
	}
	fmt.Printf("SIGNED  %s@%s\nKEY     %s\nTRUST   %s\n", responsePack.Metadata.ID, responsePack.Metadata.Version, validation.KeyID, validation.Trust)
	return nil
}

func resolvePackPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect response-pack path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("response-pack path must not be a symlink")
	}
	if info.IsDir() {
		path = filepath.Join(path, "pack.json")
		info, err = os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("inspect response-pack file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("response-pack file must not be a symlink")
		}
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("response-pack path must resolve to a regular JSON file")
	}
	if info.Size() > 4<<20 {
		return "", errors.New("response-pack file exceeds the 4 MiB safety limit")
	}
	return path, nil
}

func decodePack(data []byte) (model.ResponsePack, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var responsePack model.ResponsePack
	if err := decoder.Decode(&responsePack); err != nil {
		return model.ResponsePack{}, fmt.Errorf("decode response pack: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return model.ResponsePack{}, errors.New("response pack contains trailing JSON values")
	}
	return responsePack, nil
}

func atomicWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".pack-sign-*.json")
	if err != nil {
		return fmt.Errorf("create temporary response pack: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set response-pack permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write signed response pack: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync signed response pack: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close signed response pack: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace signed response pack: %w", err)
	}
	return nil
}
