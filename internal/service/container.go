// Package service provides dependency injection initialization for all application services.
package service

import (
	"database/sql"
	"fmt"

	"securevault/internal/auth"
	"securevault/internal/backup"
	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/logger"
	"securevault/internal/models"
	"securevault/internal/repository"
	"securevault/internal/search"
	"securevault/internal/session"
	"securevault/internal/vault"
)

// Container holds all instantiated services, repositories, and active configurations.
type Container struct {
	Config         *models.AppConfig
	DB             *sql.DB
	SessionManager *session.SessionManager
	AuthService    *auth.AuthService
	VaultService   *vault.VaultService
	BackupService  *backup.BackupService
	SearchEngine   *search.SearchEngine
	UserRepo       repository.UserRepository
	AuthRepo       repository.AuthRepository
	VaultRepo      repository.VaultRepository
	AuditRepo      repository.AuditRepository
}

// NewContainer initializes configuration, database connection, repositories, and services.
func NewContainer(configPath string) (*Container, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed loading config: %w", err)
	}

	if err := logger.InitLogger(cfg); err != nil {
		return nil, fmt.Errorf("failed initializing logger: %w", err)
	}

	db, err := database.InitDB(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to database: %w", err)
	}

	repo := repository.NewSQLiteRepository(db)
	sess := session.NewSessionManager(cfg)

	authSvc := auth.NewAuthService(repo, repo, repo, repo, sess, cfg)
	vaultSvc := vault.NewVaultService(repo, repo, sess)
	backupSvc := backup.NewBackupService(repo, repo, repo, sess, cfg)
	searchEng := search.NewSearchEngine()

	return &Container{
		Config:         cfg,
		DB:             db,
		SessionManager: sess,
		AuthService:    authSvc,
		VaultService:   vaultSvc,
		BackupService:  backupSvc,
		SearchEngine:   searchEng,
		UserRepo:       repo,
		AuthRepo:       repo,
		VaultRepo:      repo,
		AuditRepo:      repo,
	}, nil
}

// Close gracefully closes open resources like database handles.
func (c *Container) Close() {
	if c.DB != nil {
		_ = c.DB.Close()
	}
}
