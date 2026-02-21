package vex

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	types "github.com/aquasecurity/trivy/pkg/types"
)

type VEX interface {
	IsNotAffected(report *types.Report) bool
}

func retrieveExternalVEXDocument(ctx context.Context, vexUrl *url.URL, report *types.Report) (VEX, error) {
	log.DebugContext(ctx, "Retrieving external VEX document", log.String("url", vexUrl.String()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vexUrl.String(), http.NoBody)
	if err != nil {
		return nil, xerrors.Errorf("failed to create request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("unable to fetch file via HTTP: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("unable to fetch file via HTTP: status %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read VEX document: %w", err)
	}

	if bytes.HasPrefix(body, []byte("{")) {
		return NewOpenVEX(body)
	}

	return NewCSAF(body)
}

func EvaluateVEX(ctx context.Context, vexURLs []*url.URL, report *types.Report) (bool, error) {
	vexes, err := lo.MapErr(vexURLs, func(vexUrl *url.URL, _ int) (VEX, error) {
		switch vexUrl.Scheme {
		case "http", "https":
			return retrieveExternalVEXDocument(ctx, vexUrl, report)
		case "file":
			return NewCSAFFile(vexUrl)
		default:
			return nil, xerrors.Errorf("invalid scheme for external VEX document: %s", vexUrl.Scheme)
		}
	})
	if err != nil {
		return false, err
	}

	isNotAffected := lo.SomeBy(vexes, func(vex VEX) bool {
		return vex.IsNotAffected(report)
	})
	return isNotAffected, nil
}
