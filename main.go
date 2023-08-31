package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/Masterminds/semver/v3"
	macho "github.com/anchore/go-macholibre"
	"gopkg.in/yaml.v3"
)

var logVerbose bool

func main() {
	var allowConstraint string
	flag.StringVar(&allowConstraint, "allow", "*", "go versions to allow use syntax from github.com/Masterminds/semver")
	flag.BoolVar(&logVerbose, "v", false, "log stuff verbosely")
	flag.Parse()

	allRecords, err := tileVersions(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	if !allGoVersionsAreAllowed(allowConstraint, allRecords) {
		os.Exit(1)
	}
}

func allGoVersionsAreAllowed(allowConstraint string, records []goBinaryRecord) bool {
	allow, err := semver.NewConstraint(allowConstraint)
	if err != nil {
		panic(fmt.Errorf("allow constraint invalid: %w", err))
	}

	allOkay := true
	for _, record := range records {
		versionString := strings.TrimPrefix(record.GoVersion, "go")
		v, err := semver.NewVersion(versionString)
		if err != nil {
			allOkay = false
			_, _ = fmt.Fprintf(os.Stderr, "%s/%s: has binary with unparsable go version %q in for binary %s", record.ReleaseName, record.ReleaseVersion, versionString, record.Path)
			continue
		}
		if !allow.Check(v) {
			allOkay = false
			_, _ = fmt.Fprintf(os.Stderr, "%s/%s: uses not allowed go version %s in binary %s", record.ReleaseName, record.ReleaseVersion, versionString, record.Path)
			continue
		}
	}
	return allOkay
}

type goBinaryRecord struct {
	ReleaseName, ReleaseVersion, Path string
	debug.BuildInfo
}

func tileVersions(name string) ([]goBinaryRecord, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer closeAndIgnoreError(f)
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(f, stat.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to read zip file: %w", err)
	}

	var allRecords []goBinaryRecord

	// by only scanning releases, we are ignoring binaries in the embed directory... this is okay?
	for _, rf := range zr.File {
		if rf.FileInfo().IsDir() || filepath.Ext(rf.Name) != ".tgz" {
			continue
		}
		f, err := zr.Open(rf.Name)
		if err != nil {
			return nil, err
		}

		_, records, err := releaseGoVersions(f, rf.Name)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			continue
		}

		allRecords = append(allRecords, records...)
	}

	return allRecords, nil
}

var releaseManifestPattern = regexp.MustCompile(`(?mi)release\.mf`)

func releaseGoVersions(f fs.File, filePath string) (name string, _ []goBinaryRecord, _ error) {
	defer closeAndIgnoreError(f)
	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read release as gzip file: %w", err)
	}
	var (
		releaseName, releaseVersion string
		result                      []goBinaryRecord
	)
	tr := tar.NewReader(gr)
	for {
		tf, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", nil, err
		}
		if releaseManifestPattern.MatchString(tf.Name) {
			var manifest struct {
				Name    string `yaml:"name"`
				Version string `yaml:"version"`
			}
			buf, readErr := io.ReadAll(tr)
			if readErr != nil {
				return "", nil, fmt.Errorf("failed to read release manifest: %w", err)
			}
			if err := yaml.Unmarshal(buf, &manifest); err != nil {
				return "", nil, fmt.Errorf("failed to parse release manifest: %w", err)
			}
			releaseName = manifest.Name
			releaseVersion = manifest.Version
			if logVerbose {
				_, _ = fmt.Fprintf(os.Stderr, "scanning BOSH release: %s/%s\n", releaseName, releaseVersion)
			}
		}
		if tf.Size == 0 {
			continue
		}
		records, scanErr := scanCompiledPackages(tr, filepath.Join(filePath, tf.Name))
		if err != nil {
			return "", nil, scanErr
		}
		result = append(result, records...)
	}

	for i := range result {
		result[i].ReleaseName = releaseName
		result[i].ReleaseVersion = releaseVersion
	}

	return releaseName, result, nil
}

func scanCompiledPackages(reader io.Reader, filePath string) ([]goBinaryRecord, error) {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	var result []goBinaryRecord
	tr := tar.NewReader(gr)
	for {
		tf, nextErr := tr.Next()
		if nextErr != nil {
			if nextErr == io.EOF {
				break
			}
			return nil, nextErr
		}

		buf, readAllErr := io.ReadAll(tr)
		if readAllErr != nil {
			return nil, readAllErr
		}

		infos, scanErr := scanFile(tf, bytes.NewReader(buf), filepath.Join(filePath, tf.Name))
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, infos...)
	}
	return result, nil
}

func scanFile(fileHeader *tar.Header, f interface {
	io.ReaderAt
	io.Reader
}, filePath string,
) ([]goBinaryRecord, error) {
	readers := []interface {
		io.ReaderAt
		io.Reader
	}{f}
	if macho.IsUniversalMachoBinary(f) {
		list, err := macho.ExtractReaders(f)
		if err != nil {
			return nil, err
		}
		readers = readers[:0]
		for _, rd := range list {
			readers = append(readers, rd.Reader)
		}
	}

	var builds []goBinaryRecord
	for _, r := range readers {
		bi, err := buildinfo.Read(r)
		// note: the stdlib does not export the error we need to check for
		if err != nil {
			if !shouldFallBackToStrings(fileHeader) {
				return nil, nil
			}
			v, err := readGoVersionFromStringsOutput(r)
			if err == nil && v != "" {
				_, _ = fmt.Fprintf(os.Stdout, "%s\t%s\n", strings.TrimPrefix(v, "go"), filePath)
				builds = append(builds, goBinaryRecord{
					BuildInfo: debug.BuildInfo{
						GoVersion: v,
					},
					Path: filePath,
				})
				continue
			}
			return nil, nil
		}

		_, _ = fmt.Fprintf(os.Stdout, "%s\t%s\n", strings.TrimPrefix(bi.GoVersion, "go"), filePath)

		builds = append(builds, goBinaryRecord{
			BuildInfo: *bi,
			Path:      filePath,
		})
	}

	return builds, nil
}

func closeAndIgnoreError(c io.Closer) {
	_ = c.Close()
}

func shouldFallBackToStrings(header *tar.Header) bool {
	const oneMB = 1 << 20
	return !header.FileInfo().IsDir() && header.Size > oneMB && !hasIgnorableExtension(header)
}

func hasIgnorableExtension(header *tar.Header) bool {
	switch strings.TrimPrefix(filepath.Ext(header.Name), ".") {
	case "a", "txt", "jpg", "zip", "js", "gz", "go", "html", "md", "rb", "py", "sh", "erb":
		return true
	default:
		return false
	}
}

func readGoVersionFromStringsOutput(reader io.Reader) (string, error) {
	var buffer bytes.Buffer
	cmd := exec.Command("strings")
	cmd.Stdin = reader
	cmd.Stdout = &buffer
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	exp := regexp.MustCompile(` (go\d+\.\d+(\.\d+)?)`)
	matches := exp.FindAllSubmatch(buffer.Bytes(), -1)
	if len(matches) > 0 {
		return getHighestGoVersion(matches)
	}
	return "", nil
}

func getHighestGoVersion(matches [][][]byte) (string, error) {
	versions := make([]*semver.Version, 0, len(matches))
	for _, match := range matches {
		v, err := semver.NewVersion(string(match[1][2:]))
		if err != nil {
			continue
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return "", nil
	}
	slices.SortFunc(versions, func(a, b *semver.Version) int {
		return a.Compare(b)
	})
	return "go" + versions[0].String(), nil
}
