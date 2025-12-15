package auth

import "sync"

type Service struct {
	mu    sync.RWMutex
	users map[string]string
}

func New() *Service {
	return &Service{
		users: map[string]string{
			"alice": "alice123",
			"bob":   "bob123",
		},
	}
}

func (s *Service) Verify(user, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pw, ok := s.users[user]
	return ok && pw == password
}
