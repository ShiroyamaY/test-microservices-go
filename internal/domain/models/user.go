package models

type User struct {
	Id       int32
	Name     string
	PassHash []byte
}
