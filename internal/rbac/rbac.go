package rbac

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type RBAC struct {
	mu       sync.RWMutex
	Policies map[string][]string
}

func Load(path string) (*RBAC, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p map[string][]string
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &RBAC{Policies: p}, nil
}

func (r *RBAC) Reload(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var p map[string][]string
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	r.Policies = p
	return nil
}

// ⭐ Thêm hàm public để lấy danh sách Policies
func (r *RBAC) ListPolicies() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Policies
}

func (r *RBAC) Allows(user, target string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	allowed, ok := r.Policies[user]
	if !ok {
		return false
	}
	for _, a := range allowed {
		if a == "*" {
			return true
		}
		if a == target {
			return true
		}
		if strings.HasSuffix(a, "*") {
			prefix := strings.TrimSuffix(a, "*")
			if strings.HasPrefix(target, prefix) {
				return true
			}
		}
	}
	return false
}

