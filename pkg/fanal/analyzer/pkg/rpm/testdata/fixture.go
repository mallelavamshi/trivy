package rpm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/magefile/mage/target"
	"golang.org/x/xerrors"
)

const (
	WorkDir = "./work"
)

func init() {
	if err := os.MkdirAll(WorkDir, 0755); err != nil {
		panic(err)
	}
}

func downloadFile(filename, url string) error {
	slog.Info("Downloading...", slog.String("url", url))

	// Send a GET request to the URL
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return xerrors.Errorf("error sending GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	out, err := os.Create(filename)
	if err != nil {
		return xerrors.Errorf("error creating file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return xerrors.Errorf("error saving file: %v", err)
	}

	return nil
}

// ... (rest of file unchanged)
