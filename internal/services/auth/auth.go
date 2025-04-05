package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	jwt "sso/internal/lib"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		name string,
		passHash []byte,
	) (userID int64, err error)
}

type UserProvider interface {
	User(
		ctx context.Context,
		email string,
	) (*models.User, error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
}

type AppProvider interface {
	App(
		ctx context.Context,
		appID int32,
	) (*models.App, error)
}

// New returns a new instance of the Auth Service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {

	return &Auth{
		log:          log,
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

var (
	ErrInvalidCredentials = errors.New("invalID credentials")
	ErrInvalidAppID       = errors.New("invalid appID")
	ErrUserExists         = errors.New("user already exists")
)

func (auth *Auth) Login(
	ctx context.Context,
	email string,
	password []byte,
	appID int32,
) (string, error) {
	op := "auth.Login"

	log := auth.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	user, err := auth.userProvider.User(ctx, email)

	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error()),
			})

			return "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		log.Error("failed to get user", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, password); err != nil {
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := auth.appProvider.App(ctx, appID)

	if err != nil {
		log.Error("failed to get app", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

		return "", fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
	}

	token, err := jwt.NewToken(user, app, auth.tokenTTL)

	if err != nil {
		log.Error("failed to create token", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (auth *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := auth.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to generate password hash", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userId, err := auth.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

			return 0, ErrUserExists
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return userId, nil
}

func (auth *Auth) isAdmin(ctx context.Context, userID int64) (bool, error) {
	op := "auth.IsAdmin"

	log := auth.log.With(
		slog.String("op", op),
		slog.String("userID", fmt.Sprint(userID)),
	)

	log.Info("checking user is admin")

	isAdmin, err := auth.userProvider.IsAdmin(ctx, userID)

	if err != nil {
		log.Error("failed to identify if user is admin", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.Attr{Key: "error", Value: slog.StringValue(err.Error())})

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}
