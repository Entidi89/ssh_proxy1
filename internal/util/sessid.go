package util

import "github.com/google/uuid"

func NewSessionID() string {
	return uuid.New().String()
}
