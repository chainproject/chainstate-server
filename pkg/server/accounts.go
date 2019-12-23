package server

import (
	"context"
	"database/sql"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/chainproject/chainstate-server/pkg/api"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
)

func NewAccountsServer(ctx context.Context, db *sql.DB) (AccountsServer, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS accounts(
		account_id TEXT,
		description TEXT NOT NULL DEFAULT '',
		threshold INT NOT NULL DEFAULT 1,
		balance INT NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ,
		is_validator BOOL NOT NULL DEFAULT false,
		vote TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS account_signers(
		account_id TEXT,
		signer_id TEXT,
		type TEXT,
		weight INT,
		pubkey BYTEA,
		PRIMARY KEY(account_id, signer_id))`)
	if err != nil {
		return nil, err
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS account_data(
		account_id TEXT,
		data_id TEXT,
		data BYTEA,
		PRIMARY KEY(account_id, data_id))`)
	if err != nil {
		return nil, err
	}

	return &accountsServer{db}, nil
}

type AccountsServer interface {
	api.AccountsServer
	// Create creates a new account in the db
	Create(ctx context.Context, account *api.Account) (*api.Account, error)
	// SetData sets data on an account
	SetData(ctx context.Context, accountID, dataID string, data []byte) error
	// AddSigner adds a signer to an account
	AddSigner(ctx context.Context, accountID, signerID, signatureType string, weight int, pubkey []byte) error
	// DelSigner removes a signer from an account
	DelSigner(ctx context.Context, accountID, signerID string) error
	// Send transfers tokens from one account to another
	Send(ctx context.Context, from, to string, amount uint64) error
	// Merge merges the "from" account into the "to" account, deleting the "from" account
	Merge(ctx context.Context, from, to string) error
}

type accountsServer struct {
	db *sql.DB
}

// Get returns a single account
func (s *accountsServer) Get(ctx context.Context, req *api.GetAccountRequest) (*api.Account, error) {
	resp := &api.Account{
		Id:      req.GetName(),
		Signers: make(map[string]*api.Signer),
	}
	var createdAt time.Time
	err := s.getBuilder(s.db).Select(
		"description",
		"threshold",
		"balance",
		"created_at",
		"is_validator",
		"vote",
	).From("accounts").
		Where(squirrel.Eq{"account_id": req.GetName()}).
		QueryRowContext(ctx).
		Scan(
			&resp.Description,
			&resp.Threshold,
			&resp.Balance,
			&createdAt,
			&resp.IsValidator,
			&resp.Vote,
		)
	if err != nil {
		return nil, err
	}
	resp.CreatedAt, err = ptypes.TimestampProto(createdAt)
	if err != nil {
		return nil, err
	}
	rows, err := s.getBuilder(s.db).Select("signer_id", "pubkey", "type", "weight").
		Where(squirrel.Eq{"account_id": req.GetName()}).
		QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		signer := &api.Signer{}
		err = rows.Scan(&signer.Name, &signer.Pubkey, &signer.Type, &signer.Weight)
		if err != nil {
			return nil, err
		}
		resp.Signers[signer.GetName()] = signer
	}
	return resp, nil
}

// Create creates a single account
func (s *accountsServer) Create(ctx context.Context, req *api.Account) (resp *api.Account, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rErr := tx.Rollback()
			if rErr != nil {
				logrus.Error(rErr)
			}
			return
		}
		err = tx.Commit()
	}()
	createdAt, err := ptypes.Timestamp(req.GetCreatedAt())
	if err != nil {
		return nil, err
	}
	_, err = s.getBuilder(tx).Insert("accounts").
		Columns(
			"account_id",
			"description",
			"threshold",
			"balance",
			"created_at",
			"is_validator",
			"vote",
		).
		Values(
			req.GetId(),
			req.GetDescription(),
			req.GetThreshold(),
			req.GetBalance(),
			createdAt,
			req.GetIsValidator(),
			req.GetVote(),
		).
		ExecContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, signer := range req.GetSigners() {
		_, err = s.getBuilder(tx).Insert("account_signers").
			Columns(
				"account_id",
				"signer_id",
				"pubkey",
				"type",
				"weight",
			).
			Values(
				req.GetId(),
				signer.GetName(),
				signer.GetPubkey(),
				signer.GetType(),
				signer.GetWeight(),
			).
			ExecContext(ctx)
		if err != nil {
			return nil, err
		}
	}
	return req, nil
}

// SetData sets data on an account
func (s *accountsServer) SetData(ctx context.Context, accountID, dataID string, data []byte) error {
	_, err := s.getBuilder(s.db).Insert("account_data").Columns("account_id", "data_id", "data").
		Values(accountID, dataID, data).ExecContext(ctx)
	return err
}

// GetData returns a single data object
func (s *accountsServer) GetData(ctx context.Context, req *api.GetDataRequest) (*api.GetDataResponse, error) {
	resp := &api.GetDataResponse{
		Key: req.GetKey(),
	}
	err := s.getBuilder(s.db).Select("data").From("accounts_data").Where(squirrel.Eq{
		"account_id": req.GetName(),
		"data_id":    req.GetKey(),
	}).QueryRowContext(ctx).
		Scan(&resp.Data)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AddSigner adds a signer to an account
func (s *accountsServer) AddSigner(ctx context.Context, accountID, signerID, signatureType string, weight int, pubkey []byte) error {
	_, err := s.getBuilder(s.db).Insert("account_signers").
		Columns(
			"account_id",
			"signer_id",
			"pubkey",
			"type",
			"weight",
		).
		Values(
			accountID,
			signerID,
			pubkey,
			signatureType,
			weight,
		).
		ExecContext(ctx)
	return err
}

// DelSigner removes a signer from an account
func (s *accountsServer) DelSigner(ctx context.Context, accountID, signerID string) error {
	_, err := s.getBuilder(s.db).Delete("account_signers").Where(squirrel.Eq{
		"account_id": accountID,
		"signer_id":  signerID,
	}).ExecContext(ctx)
	return err
}

// ListData returns a stream of data objects attached to the specified account
func (s *accountsServer) ListData(req *api.ListDataRequest, resp api.Accounts_ListDataServer) error {
	rows, err := s.getBuilder(s.db).Select("data", "data_id").From("accounts_data").Where(squirrel.Eq{
		"account_id": req.GetName(),
	}).QueryContext(resp.Context())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		d := &api.GetDataResponse{}
		err = rows.Scan(&d.Data, &d.Key)
		if err != nil {
			return err
		}
		err = resp.Send(d)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *accountsServer) Merge(ctx context.Context, from, to string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rErr := tx.Rollback()
			if rErr != nil {
				logrus.Error(rErr)
			}
			return
		}
		err = tx.Commit()
	}()
	var fromBalance, toBalance uint64
	err = s.getBuilder(tx).Select("accounts").
		Columns("balance").
		Where(squirrel.Eq{"account_id": from}).
		QueryRowContext(ctx).
		Scan(&fromBalance)
	if err != nil {
		return err
	}
	err = s.getBuilder(tx).Select("accounts").
		Columns("balance").
		Where(squirrel.Eq{"account_id": to}).
		QueryRowContext(ctx).
		Scan(&toBalance)
	if err != nil {
		return err
	}
	toBalance += fromBalance
	_, err = s.getBuilder(tx).Delete("accounts").
		Where(squirrel.Eq{"account_id": from}).
		ExecContext(ctx)
	if err != nil {
		return err
	}
	_, err = s.getBuilder(tx).Update("accounts").
		Set("balance", toBalance).
		Where(squirrel.Eq{"account_id": to}).
		ExecContext(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (s *accountsServer) Send(ctx context.Context, from, to string, amount uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rErr := tx.Rollback()
			if rErr != nil {
				logrus.Error(rErr)
			}
			return
		}
		err = tx.Commit()
	}()
	var fromBalance, toBalance uint64
	err = s.getBuilder(tx).Select("accounts").
		Columns("balance").
		Where(squirrel.Eq{"account_id": from}).
		QueryRowContext(ctx).
		Scan(&fromBalance)
	if err != nil {
		return err
	}
	err = s.getBuilder(tx).Select("accounts").
		Columns("balance").
		Where(squirrel.Eq{"account_id": to}).
		QueryRowContext(ctx).
		Scan(&toBalance)
	if err != nil {
		return err
	}
	fromBalance -= amount
	toBalance += amount
	_, err = s.getBuilder(tx).Update("accounts").
		Set("balance", fromBalance).
		Where(squirrel.Eq{"account_id": from}).
		ExecContext(ctx)
	if err != nil {
		return err
	}
	_, err = s.getBuilder(tx).Update("accounts").
		Set("balance", toBalance).
		Where(squirrel.Eq{"account_id": to}).
		ExecContext(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (s *accountsServer) getBuilder(runner squirrel.BaseRunner) squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).RunWith(runner)
}
