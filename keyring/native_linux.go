//go:build linux

package keyring

import (
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// Linux uses the freedesktop Secret Service (GNOME Keyring, KWallet, KeePassXC)
// on the session bus. The "plain" session transfers secrets only over the
// user's own session bus; any process able to read it can already query the
// unlocked keyring.
const (
	secretServiceBus        = "org.freedesktop.secrets"
	secretServicePath       = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface      = "org.freedesktop.Secret.Service"
	secretPromptTimeout     = 2 * time.Minute
	secretNoPrompt          = dbus.ObjectPath("/")
	secretItemLabelProperty = "org.freedesktop.Secret.Item.Label"
	secretItemAttrsProperty = "org.freedesktop.Secret.Item.Attributes"
)

// ErrStoreMissing reports that this account has no usable credential store.
var ErrStoreMissing = errSecretServiceUnavailable

var errSecretServiceUnavailable = errors.New("No system keyring is available. Install and unlock a Secret Service keyring such as GNOME Keyring or KWallet, then retry.")

type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type nativeBackend struct{ label string }

// Native returns the Secret Service backend; label names saved items.
func Native(label string) Backend { return nativeBackend{label} }

type secretServiceSession struct {
	conn    *dbus.Conn
	service dbus.BusObject
	path    dbus.ObjectPath
}

func secretServiceError(operation string, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrAccessDenied) || errors.Is(err, errSecretServiceUnavailable) {
		return err
	}
	name := ""
	var value dbus.Error
	var pointer *dbus.Error
	if errors.As(err, &value) {
		name = value.Name
	} else if errors.As(err, &pointer) {
		name = pointer.Name
	}
	switch name {
	case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner", "org.freedesktop.DBus.Error.UnknownObject",
		"org.freedesktop.Secret.Error.NoSuchObject":
		return errSecretServiceUnavailable
	case "org.freedesktop.Secret.Error.IsLocked", "org.freedesktop.DBus.Error.AccessDenied":
		return ErrAccessDenied
	case "":
		return fmt.Errorf("the system keyring could not %s credentials: %v", operation, err)
	}
	return fmt.Errorf("the system keyring could not %s credentials (%s)", operation, name)
}

func openR2SecretService() (*secretServiceSession, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, errSecretServiceUnavailable
	}
	service := conn.Object(secretServiceBus, secretServicePath)
	var output dbus.Variant
	var path dbus.ObjectPath
	if err := service.Call(secretServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &path); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &secretServiceSession{conn: conn, service: service, path: path}, nil
}

func (s *secretServiceSession) close() {
	_ = s.conn.Object(secretServiceBus, s.path).Call("org.freedesktop.Secret.Session.Close", 0).Err
	_ = s.conn.Close()
}

// prompt runs a keyring dialog. Dismissing it, or leaving it unanswered, counts
// as refusal so background work does not keep reopening the dialog.
func (s *secretServiceSession) prompt(path dbus.ObjectPath) error {
	if path == "" || path == secretNoPrompt {
		return nil
	}
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(path), dbus.WithMatchInterface("org.freedesktop.Secret.Prompt"), dbus.WithMatchMember("Completed")}
	if err := s.conn.AddMatchSignal(match...); err != nil {
		return err
	}
	defer s.conn.RemoveMatchSignal(match...)
	signals := make(chan *dbus.Signal, 4)
	s.conn.Signal(signals)
	defer s.conn.RemoveSignal(signals)
	prompt := s.conn.Object(secretServiceBus, path)
	if err := prompt.Call("org.freedesktop.Secret.Prompt.Prompt", 0, "").Err; err != nil {
		return err
	}
	timer := time.NewTimer(secretPromptTimeout)
	defer timer.Stop()
	for {
		select {
		case signal, ok := <-signals:
			if !ok {
				return errSecretServiceUnavailable
			}
			if signal.Path != path || signal.Name != "org.freedesktop.Secret.Prompt.Completed" || len(signal.Body) == 0 {
				continue
			}
			if dismissed, _ := signal.Body[0].(bool); dismissed {
				return ErrAccessDenied
			}
			return nil
		case <-timer.C:
			_ = prompt.Call("org.freedesktop.Secret.Prompt.Dismiss", 0).Err
			return ErrAccessDenied
		}
	}
}

func (s *secretServiceSession) unlock(paths []dbus.ObjectPath) error {
	if len(paths) == 0 {
		return nil
	}
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.service.Call(secretServiceIface+".Unlock", 0, paths).Store(&unlocked, &prompt); err != nil {
		return err
	}
	return s.prompt(prompt)
}

func secretServiceAttributes(service, key string) map[string]string {
	return map[string]string{"service": service, "account": key}
}

func (s *secretServiceSession) items(service, key string) ([]dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	if err := s.service.Call(secretServiceIface+".SearchItems", 0, secretServiceAttributes(service, key)).Store(&unlocked, &locked); err != nil {
		return nil, err
	}
	if err := s.unlock(locked); err != nil {
		return nil, err
	}
	return append(unlocked, locked...), nil
}

func withR2SecretService(operation string, run func(*secretServiceSession) error) error {
	session, err := openR2SecretService()
	if err != nil {
		return secretServiceError(operation, err)
	}
	defer session.close()
	return secretServiceError(operation, run(session))
}

func (nativeBackend) Load(service, key string) ([]byte, error) {
	var value []byte
	err := withR2SecretService("read", func(s *secretServiceSession) error {
		items, err := s.items(service, key)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return ErrNotFound
		}
		var secret secretServiceSecret
		if err := s.conn.Object(secretServiceBus, items[0]).Call("org.freedesktop.Secret.Item.GetSecret", 0, s.path).Store(&secret); err != nil {
			return err
		}
		value = secret.Value
		return nil
	})
	if err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func (b nativeBackend) Save(service, key string, value []byte) error {
	return withR2SecretService("save", func(s *secretServiceSession) error {
		var collection dbus.ObjectPath
		if err := s.service.Call(secretServiceIface+".ReadAlias", 0, "default").Store(&collection); err != nil {
			return err
		}
		if collection == "" || collection == secretNoPrompt {
			return errSecretServiceUnavailable
		}
		if err := s.unlock([]dbus.ObjectPath{collection}); err != nil {
			return err
		}
		properties := map[string]dbus.Variant{
			secretItemLabelProperty: dbus.MakeVariant(b.label),
			secretItemAttrsProperty: dbus.MakeVariant(secretServiceAttributes(service, key)),
		}
		secret := secretServiceSecret{Session: s.path, Parameters: []byte{}, Value: value, ContentType: "application/octet-stream"}
		var item, prompt dbus.ObjectPath
		if err := s.conn.Object(secretServiceBus, collection).Call("org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, true).Store(&item, &prompt); err != nil {
			return err
		}
		return s.prompt(prompt)
	})
}

func (nativeBackend) Delete(service, key string) error {
	return withR2SecretService("delete", func(s *secretServiceSession) error {
		items, err := s.items(service, key)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return ErrNotFound
		}
		for _, item := range items {
			var prompt dbus.ObjectPath
			if err := s.conn.Object(secretServiceBus, item).Call("org.freedesktop.Secret.Item.Delete", 0).Store(&prompt); err != nil {
				return err
			}
			if err := s.prompt(prompt); err != nil {
				return err
			}
		}
		return nil
	})
}
