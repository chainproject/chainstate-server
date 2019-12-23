package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/Masterminds/squirrel"
	"github.com/chainproject/chainstate-server/pkg/api"
	"github.com/chainproject/chainstate-server/pkg/signatures"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewTransactionsServer(ctx context.Context, db *sql.DB, accountsServer api.AccountsServer) (api.TransactionServer, error) {
	return &transactionServer{db, accountsServer}, nil
}

type transactionServer struct {
	db       *sql.DB
	accounts AccountsServer
}

// Verify checks if all needed signatures are in place + all prerequirements are fullfilled for this TX to be executed
// This includes existence and balance checks.
func (s *transactionServer) Verify(ctx context.Context, tx *api.Transaction) (resp *api.VerifyResponse, err error) {
	switch tx.GetType() {
	case api.Transaction_GENESIS:
		err = s.verifyGenesis(ctx, tx)
	case api.Transaction_CREATE_ACCOUNT:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_MERGE_ACCOUNT:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SEND:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_VALIDATOR_FLAG:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_VOTE_VALIDATOR:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_ADD_SIGNER:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_REMOVE_SIGNER:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_THRESHOLD:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_DATA:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_EXECUTE:
		err = s.verifySignatures(ctx, tx)
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown transaction type")
	}
	return &api.VerifyResponse{}, nil
}

// Apply applies a transaction against the current ledger state
func (s *transactionServer) Apply(ctx context.Context, tx *api.Transaction) (*api.ApplyResponse, error) {
	switch tx.GetType() {
	case api.Transaction_GENESIS:
		err = s.verifyGenesis(ctx, tx)
	case api.Transaction_CREATE_ACCOUNT:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_MERGE_ACCOUNT:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SEND:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_VALIDATOR_FLAG:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_VOTE_VALIDATOR:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_ADD_SIGNER:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_REMOVE_SIGNER:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_THRESHOLD:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_SET_DATA:
		err = s.verifySignatures(ctx, tx)
	case api.Transaction_EXECUTE:
		err = s.verifySignatures(ctx, tx)
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown transaction type")
	}
	return &api.ApplyResponse{}, nil
}

func (s *transactionServer) verifyGenesis(ctx context.Context, tx *api.Transaction) error {
	row := s.getBuilder(s.db).Select("accounts").Columns("count(*)").QueryRowContext(ctx)
	var count int
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("there are already some accounts, genesis seems to be a bad idea in this situation")
	}
	return nil
}

func (s *transactionServer) verifySignatures(ctx context.Context, tx *api.Transaction) error {
	account, err := s.accounts.Get(ctx, &api.GetAccountRequest{Name: tx.SourceAccount})
	if err != nil {
		return err
	}
	var sum uint64
	for name, sig := range tx.Signatures {
		signer, ok := account.Signers[name]
		if !ok {
			return fmt.Errorf("unknown signer %v", name)
		}
		algo, err := signatures.GetByName(signer.Type)
		if err != nil {
			return err
		}
		txCopy := proto.Clone(tx)
		txCopy.Signatures = nil
		pr, pw := io.Pipe()
		marshaler := &jsonpb.Marshaler{}
		go marshaler.Marshal(pw, txCopy)
		err = algo.Verify(pr, sig, signer.Pubkey)
		if err != nil {
			return err
		}
		sum += signer.Weight
	}
	if sum < account.Threshold {
		return errors.New("not enough signatures")
	}
	return nil
}

func (s *transactionServer) getBuilder(runner squirrel.BaseRunner) squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).RunWith(runner)
}
