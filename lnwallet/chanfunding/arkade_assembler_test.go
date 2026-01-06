package chanfunding

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// mockArkadeClient is a mock implementation of the ArkadeClient interface
// for testing purposes.
type mockArkadeClient struct {
	vtxos              []VTXO
	balance            btcutil.Amount
	available          bool
	fundingTx          *wire.MsgTx
	signedFundingTx    *wire.MsgTx
	aspPubKey          *btcec.PublicKey
	createFundingErr   error
	signFundingErr     error
	listVTXOsErr       error
	getBalanceErr      error
	refreshErr         error
	refreshedVTXO      *VTXO
}

func (m *mockArkadeClient) ListVTXOs(_ context.Context) ([]VTXO, error) {
	if m.listVTXOsErr != nil {
		return nil, m.listVTXOsErr
	}
	return m.vtxos, nil
}

func (m *mockArkadeClient) GetVTXOBalance(_ context.Context) (btcutil.Amount, error) {
	if m.getBalanceErr != nil {
		return 0, m.getBalanceErr
	}
	return m.balance, nil
}

func (m *mockArkadeClient) CreateFundingTransaction(_ context.Context,
	_ btcutil.Address, _ btcutil.Amount) (*wire.MsgTx, error) {

	if m.createFundingErr != nil {
		return nil, m.createFundingErr
	}
	return m.fundingTx, nil
}

func (m *mockArkadeClient) SignFundingTransaction(_ context.Context,
	_ *wire.MsgTx) (*wire.MsgTx, error) {

	if m.signFundingErr != nil {
		return nil, m.signFundingErr
	}
	return m.signedFundingTx, nil
}

func (m *mockArkadeClient) RefreshVTXO(_ context.Context,
	_ string) (*VTXO, error) {

	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return m.refreshedVTXO, nil
}

func (m *mockArkadeClient) GetASPPubKey(_ context.Context) (*btcec.PublicKey, error) {
	return m.aspPubKey, nil
}

func (m *mockArkadeClient) IsAvailable(_ context.Context) bool {
	return m.available
}

// newTestKeyPair generates a new key pair for testing.
func newTestKeyPair(t *testing.T) (*btcec.PrivateKey, *btcec.PublicKey) {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return priv, priv.PubKey()
}

// TestArkadeAssemblerProvisionChannel tests the ProvisionChannel method of
// the ArkadeAssembler.
func TestArkadeAssemblerProvisionChannel(t *testing.T) {
	t.Parallel()

	fundingAmt := btcutil.Amount(100000)
	client := &mockArkadeClient{
		available: true,
		balance:   fundingAmt,
	}

	assembler := NewArkadeAssembler(
		fundingAmt, client, &chaincfg.MainNetParams, true,
	)

	tests := []struct {
		name        string
		req         *Request
		expectErr   bool
		errContains string
	}{
		{
			name: "valid request",
			req: &Request{
				LocalAmt:  fundingAmt,
				RemoteAmt: 0,
			},
			expectErr: false,
		},
		{
			name: "subtract fees not supported",
			req: &Request{
				LocalAmt:     fundingAmt,
				RemoteAmt:    0,
				SubtractFees: true,
			},
			expectErr:   true,
			errContains: "SubtractFees not supported",
		},
		{
			name: "fund up to max not supported",
			req: &Request{
				LocalAmt:       0,
				RemoteAmt:      0,
				FundUpToMaxAmt: fundingAmt,
			},
			expectErr:   true,
			errContains: "FundUpToMaxAmt",
		},
		{
			name: "amount mismatch",
			req: &Request{
				LocalAmt:  fundingAmt / 2,
				RemoteAmt: 0,
			},
			expectErr:   true,
			errContains: "intent doesn't match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intent, err := assembler.ProvisionChannel(tc.req)

			if tc.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
				require.Nil(t, intent)
			} else {
				require.NoError(t, err)
				require.NotNil(t, intent)

				arkIntent, ok := intent.(*ArkadeIntent)
				require.True(t, ok)
				require.Equal(t, ArkadeStateInit, arkIntent.State)
			}
		})
	}
}

// TestArkadeAssemblerNoClient tests that ProvisionChannel fails when no
// client is configured.
func TestArkadeAssemblerNoClient(t *testing.T) {
	t.Parallel()

	assembler := NewArkadeAssembler(
		100000, nil, &chaincfg.MainNetParams, true,
	)

	_, err := assembler.ProvisionChannel(&Request{
		LocalAmt:  100000,
		RemoteAmt: 0,
	})

	require.ErrorIs(t, err, ErrArkadeNotConfigured)
}

// TestArkadeIntentBindKeys tests the BindKeys method of ArkadeIntent.
func TestArkadeIntentBindKeys(t *testing.T) {
	t.Parallel()

	fundingAmt := btcutil.Amount(100000)
	client := &mockArkadeClient{
		available: true,
		balance:   fundingAmt,
	}

	assembler := NewArkadeAssembler(
		fundingAmt, client, &chaincfg.MainNetParams, true,
	)

	intent, err := assembler.ProvisionChannel(&Request{
		LocalAmt:  fundingAmt,
		RemoteAmt: 0,
	})
	require.NoError(t, err)

	arkIntent, ok := intent.(*ArkadeIntent)
	require.True(t, ok)
	require.Equal(t, ArkadeStateInit, arkIntent.State)

	// Generate test keys.
	_, localPub := newTestKeyPair(t)
	_, remotePub := newTestKeyPair(t)

	localKey := &keychain.KeyDescriptor{
		PubKey: localPub,
	}

	// Bind the keys.
	arkIntent.BindKeys(localKey, remotePub)

	require.Equal(t, ArkadeStateOutputKnown, arkIntent.State)
	require.Equal(t, localPub, arkIntent.localKey.PubKey)
	require.Equal(t, remotePub, arkIntent.remoteKey)
}

// TestArkadeIntentCancel tests the Cancel method of ArkadeIntent.
func TestArkadeIntentCancel(t *testing.T) {
	t.Parallel()

	fundingAmt := btcutil.Amount(100000)
	client := &mockArkadeClient{
		available: true,
		balance:   fundingAmt,
	}

	assembler := NewArkadeAssembler(
		fundingAmt, client, &chaincfg.MainNetParams, true,
	)

	intent, err := assembler.ProvisionChannel(&Request{
		LocalAmt:  fundingAmt,
		RemoteAmt: 0,
	})
	require.NoError(t, err)

	arkIntent, ok := intent.(*ArkadeIntent)
	require.True(t, ok)

	// Cancel the intent.
	arkIntent.Cancel()

	// Verify the state changed to canceled.
	require.Equal(t, ArkadeStateCanceled, arkIntent.State)

	// Verify the ready channel received an error.
	select {
	case err := <-arkIntent.ArkadeReady:
		require.ErrorIs(t, err, ErrArkadeIntentCanceled)
	default:
		t.Fatal("expected error on ArkadeReady channel")
	}
}

// TestArkadeAssemblerShouldPublish tests the ShouldPublishFundingTx method.
func TestArkadeAssemblerShouldPublish(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		shouldPublish bool
	}{
		{
			name:          "should publish",
			shouldPublish: true,
		},
		{
			name:          "should not publish",
			shouldPublish: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assembler := NewArkadeAssembler(
				100000, &mockArkadeClient{}, &chaincfg.MainNetParams,
				tc.shouldPublish,
			)

			require.Equal(t, tc.shouldPublish, assembler.ShouldPublishFundingTx())
		})
	}
}

// TestArkadeStateString tests the String method of ArkadeState.
func TestArkadeStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    ArkadeState
		expected string
	}{
		{ArkadeStateInit, "init"},
		{ArkadeStateOutputKnown, "output_known"},
		{ArkadeStateFundingCreated, "funding_created"},
		{ArkadeStateFundingSigned, "funding_signed"},
		{ArkadeStateComplete, "complete"},
		{ArkadeStateCanceled, "canceled"},
		{ArkadeState(99), "<unknown(99)>"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.state.String())
		})
	}
}

// TestArkadeIntentCreateFundingTxASPUnavailable tests that CreateFundingTx
// returns an error when the ASP is unavailable.
func TestArkadeIntentCreateFundingTxASPUnavailable(t *testing.T) {
	t.Parallel()

	fundingAmt := btcutil.Amount(100000)
	client := &mockArkadeClient{
		available: false,
		balance:   fundingAmt,
	}

	assembler := NewArkadeAssembler(
		fundingAmt, client, &chaincfg.MainNetParams, true,
	)

	intent, err := assembler.ProvisionChannel(&Request{
		LocalAmt:  fundingAmt,
		RemoteAmt: 0,
	})
	require.NoError(t, err)

	arkIntent, ok := intent.(*ArkadeIntent)
	require.True(t, ok)

	// Bind keys to move to OutputKnown state.
	_, localPub := newTestKeyPair(t)
	_, remotePub := newTestKeyPair(t)
	arkIntent.BindKeys(&keychain.KeyDescriptor{PubKey: localPub}, remotePub)

	// Try to create funding tx with unavailable ASP.
	err = arkIntent.CreateFundingTx(context.Background())
	require.ErrorIs(t, err, ErrArkadeASPUnavailable)
}

// TestArkadeIntentCreateFundingTxInsufficientBalance tests that CreateFundingTx
// returns an error when VTXO balance is insufficient.
func TestArkadeIntentCreateFundingTxInsufficientBalance(t *testing.T) {
	t.Parallel()

	fundingAmt := btcutil.Amount(100000)
	client := &mockArkadeClient{
		available: true,
		balance:   fundingAmt / 2, // Insufficient balance
	}

	assembler := NewArkadeAssembler(
		fundingAmt, client, &chaincfg.MainNetParams, true,
	)

	intent, err := assembler.ProvisionChannel(&Request{
		LocalAmt:  fundingAmt,
		RemoteAmt: 0,
	})
	require.NoError(t, err)

	arkIntent, ok := intent.(*ArkadeIntent)
	require.True(t, ok)

	// Bind keys to move to OutputKnown state.
	_, localPub := newTestKeyPair(t)
	_, remotePub := newTestKeyPair(t)
	arkIntent.BindKeys(&keychain.KeyDescriptor{PubKey: localPub}, remotePub)

	// Try to create funding tx with insufficient balance.
	err = arkIntent.CreateFundingTx(context.Background())
	require.ErrorIs(t, err, ErrInsufficientVTXOBalance)
}

// TestVTXOStruct tests the VTXO struct fields.
func TestVTXOStruct(t *testing.T) {
	t.Parallel()

	_, pubKey := newTestKeyPair(t)

	vtxo := VTXO{
		ID:           "test-vtxo-id",
		Amount:       btcutil.Amount(50000),
		ExpiryHeight: 700000,
		Outpoint: wire.OutPoint{
			Hash:  [32]byte{1, 2, 3},
			Index: 0,
		},
		RedeemScript: []byte{0x00, 0x14},
		OwnerPubKey:  pubKey,
	}

	require.Equal(t, "test-vtxo-id", vtxo.ID)
	require.Equal(t, btcutil.Amount(50000), vtxo.Amount)
	require.Equal(t, uint32(700000), vtxo.ExpiryHeight)
	require.Equal(t, pubKey, vtxo.OwnerPubKey)
}
