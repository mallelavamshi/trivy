package apk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	builtinos "os"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/hook"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	apkIndexURL = "https://dl-cdn.alpinelinux.org/alpine/%s/main/%s/APKINDEX.tar.gz"
)

type Analyzer struct{}

type pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type apkIndex struct {
	Packages []pkg `json:"packages"`
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(ctx context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var reader io.ReadCloser
	var err error
	file, ok := target.Content.(artifact.File)
	if ok {
		reader, err = file.Open()
		if err != nil {
			return nil, xerrors.Errorf("file open error: %w", err)
		}
		defer reader.Close()
	} else {
		url := fmt.Sprintf(apkIndexURL, target.OS.Distro.Version, target.Arch)

		log.DebugContext(ctx, "Fetching APKINDEX archive", log.String("url", url))

		// nolint
		ctx := context.Background()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, xerrors.Errorf("failed to fetch APKINDEX archive: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, xerrors.Errorf("failed to fetch APKINDEX archive: status %s", resp.Status)
		}

		reader = resp.Body
	}

	apkPkgs, err := parseAPKIndex(reader)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse APKINDEX archive: %w", err)
	}

	pkgs, err := a.trivyPkgs(apkPkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to convert APK packages: %w", err)
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{{
			FilePath: target.FilePath,
			Packages: pkgs,
		}},
	}, nil
}

// ... (rest of file unchanged)
