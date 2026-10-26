package r2connect_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/knothhe/r2connect"
	"github.com/knothhe/r2connect/keyring"
	"github.com/knothhe/r2connect/loopback"
)

const redirectURI = "http://localhost:18796/oauth/cloudflare/callback"

func openBrowser(string) error { return nil }

// A complete integration: sign in, choose a bucket, use its credentials and
// disconnect. See docs/integration.md for each step.
func Example() {
	ctx := context.Background()
	client := r2connect.NewClient("your-public-client-id")
	manager := r2connect.NewManager(client, r2connect.ManagerOptions{
		Secrets:         keyring.New("com.example.app.r2", "Example credentials"),
		State:           r2connect.FileStateStore{Path: filepath.Join("data", "r2-oauth-state.json")},
		TokenNamePrefix: "example-",
	})

	if _, err := loopback.Authorize(ctx, client, loopback.Options{RedirectURI: redirectURI, Accept: manager.Authorize}, openBrowser); err != nil {
		fmt.Println("sign-in failed:", err)
		return
	}
	accounts, err := manager.Accounts(ctx)
	if err != nil || len(accounts) == 0 {
		return
	}
	buckets, err := manager.Buckets(ctx, accounts[0].ID, "default")
	if err != nil || len(buckets) == 0 {
		return
	}
	conn, err := manager.Connect(ctx, accounts[0].ID, buckets[0].Name, "default")
	if err != nil {
		return
	}

	// Before each sync: renewed automatically when close to expiry.
	creds, err := manager.Credentials(ctx, conn)
	if err != nil {
		return
	}
	endpoint, _ := r2connect.Endpoint(conn.AccountID, conn.Jurisdiction)
	fmt.Println(endpoint, creds.AccessKeyID != "")

	_ = manager.Disconnect(ctx)
}

// A sign-in the user can cancel, reporting its result before the browser page
// is written.
func ExampleManager_Authorize() {
	client := r2connect.NewClient("your-public-client-id")
	manager := r2connect.NewManager(client, r2connect.ManagerOptions{
		Secrets: keyring.New("com.example.app.r2", "Example credentials"),
		State:   r2connect.FileStateStore{Path: filepath.Join("data", "r2-oauth-state.json")},
	})
	flow, err := loopback.Start(client, loopback.Options{
		RedirectURI: redirectURI,
		Accept:      manager.Authorize,
		Done: func(err error) {
			switch {
			case err == nil:
				fmt.Println("connected")
			case errors.Is(err, loopback.ErrDenied):
				fmt.Println("click Edit Permissions and turn on Account API Tokens Write, then retry")
			case errors.Is(err, context.Canceled):
			default:
				fmt.Println(err)
			}
		},
	})
	if err != nil {
		fmt.Println(err) // loopback.ErrListen when the port is busy
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	go func() {
		defer cancel()
		_, _ = flow.Wait(ctx)
	}()
	_ = openBrowser(flow.URL())
	// Call cancel when the user clicks Cancel.
}
