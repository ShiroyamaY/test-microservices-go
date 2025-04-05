package jwt

import (
	"github.com/golang-jwt/jwt"
	"sso/internal/domain/models"
	"time"
)

func NewToken(user *models.User, app *models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["userId"] = user.Id
	claims["email"] = user.Name
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.Id

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
