package chanfunding

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrArkadeNotConfigured is returned when Arkade funding is requested
	// but no Arkade client is configured.
	ErrArkadeNotConfigured = errors.New("arkade client not configured")

	// ErrInsufficientVTXOBalance is returned when the VTXO balance is
	// insufficient to fund the channel.
	ErrInsufficientVTXOBalance = errors.New("insufficient VTXO balance")

	// ErrArkadeIntentCanceled is returned when the Arkade funding intent
	// is canceled.
	ErrArkadeIntentCanceled = errors.New("arkade funding intent canceled")

	// ErrArkadeVTXOExpired is returned when the VTXO used for funding has
	// expired.
	ErrArkadeVTXOExpired = errors.New("VTXO has expired")

	// ErrArkadeServerUnavailable is returned when the Arkade Server
	// is unavailable.
	ErrArkadeServerUnavailable = errors.New("arkade server unavailable")
)

// VTXO represents a Virtual Transaction Output from the Ark protocol.
// VTXOs are off-chain UTXOs that exist within an Arkade Server's
// tree structure and can be used to fund Lightning channels.
type VTXO struct {
	// ID is the unique identifier of the VTXO.
	ID string

	// Amount is the value of the VTXO in satoshis.
	Amount btcutil.Amount

	// ExpiryHeight is the block height at which this VTXO expires.
	// After this height, the VTXO must be renewed or it will be swept
	// by the Arkade Server.
	ExpiryHeight uint32

	// Outpoint is the on-chain outpoint that anchors this VTXO.
	// This is the root of the Ark tree that contains this VTXO.
	Outpoint wire.OutPoint

	// RedeemScript is the script needed to spend this VTXO.
	RedeemScript []byte

	// OwnerPubKey is the public key of the VTXO owner.
	OwnerPubKey *btcec.PublicKey

	// Tapscripts contains the encoded tapscript leaves for this VTXO.
	Tapscripts []string

	// ExpiresAt is the time at which this VTXO expires.
	ExpiresAt time.Time

	// Preconfirmed indicates if this VTXO is preconfirmed (instant).
	Preconfirmed bool
}

// RelativeLocktime represents a relative timelock that can be either
// block-based or time-based, following BIP68.
type RelativeLocktime struct {
	// Type indicates if this is a block-based or time-based locktime.
	// 0 = blocks, 1 = time (512 second units)
	Type uint8

	// Value is the locktime value. For blocks, this is the number of blocks.
	// For time, this is the number of 512-second intervals.
	Value uint32
}

// Sequence returns the BIP68 sequence number for this relative locktime.
func (r RelativeLocktime) Sequence() (uint32, error) {
	const (
		sequenceLocktimeDisableFlag = 1 << 31
		sequenceLocktimeTypeFlag    = 1 << 22
		sequenceLocktimeMask        = 0x0000ffff
	)

	if r.Value > sequenceLocktimeMask {
		return 0, fmt.Errorf("locktime value %d exceeds maximum %d",
			r.Value, sequenceLocktimeMask)
	}

	sequence := r.Value & sequenceLocktimeMask
	if r.Type == 1 {
		sequence |= sequenceLocktimeTypeFlag
	}

	return sequence, nil
}

// ArkadeClient is an interface for communicating with an Arkade Server
// (Operator) to manage VTXOs and create channel funding transactions.
//
// This interface is designed to be compatible with the Arkade go-sdk
// (github.com/arkade-os/go-sdk) but can be implemented by any Ark client.
type ArkadeClient interface {
	// ListVTXOs returns all VTXOs owned by the wallet that can be used
	// for channel funding.
	ListVTXOs(ctx context.Context) ([]VTXO, error)

	// GetVTXOBalance returns the total balance of all spendable VTXOs.
	GetVTXOBalance(ctx context.Context) (btcutil.Amount, error)

	// CreateFundingTransaction creates a funding transaction that spends
	// VTXOs to fund a Lightning channel. The transaction will have a
	// single output at the specified funding address.
	//
	// The returned transaction is unsigned and needs to be signed by the
	// Arkade Server in a collaborative signing round.
	CreateFundingTransaction(ctx context.Context, fundingAddr btcutil.Address,
		amount btcutil.Amount) (*wire.MsgTx, error)

	// SignFundingTransaction requests the Arkade Server to collaboratively
	// sign the funding transaction. This is needed because VTXOs require
	// cooperation from the Arkade Server to spend.
	SignFundingTransaction(ctx context.Context,
		tx *wire.MsgTx) (*wire.MsgTx, error)

	// RenewVTXO requests the Arkade Server to renew a VTXO, extending its
	// expiry time. This should be called before a VTXO expires.
	RenewVTXO(ctx context.Context, vtxoID string) (*VTXO, error)

	// GetServerPubKey returns the Arkade Server's public key used for
	// collaborative signing.
	GetServerPubKey(ctx context.Context) (*btcec.PublicKey, error)

	// IsAvailable checks if the Arkade Server is available and responding.
	IsAvailable(ctx context.Context) bool

	// GetUnilateralExitDelay returns the CSV delay required for
	// unilateral exit from VTXOs.
	GetUnilateralExitDelay(ctx context.Context) (RelativeLocktime, error)

	// CollaborativeExit performs a collaborative exit from VTXOs to an
	// on-chain address. This is faster than unilateral exit but requires
	// Arkade Server cooperation.
	CollaborativeExit(ctx context.Context, addr string,
		amount uint64) (string, error)
}

// LightningChannelScriptBuilder creates VTXO scripts for Lightning Network
// channels. It implements the dual-path Taproot structure required by
// Arkade Lightning Channels:
//
// Script Path 1: Standard 2-of-2 multisig (Alice + Bob)
// Script Path 2: Same 2-of-2 multisig + CSV timeout for Ark unilateral exit
//
// This allows:
// - Normal Lightning operation using standard commitment transactions
// - Unilateral exit if Arkade Server becomes unavailable
//
// The Server key does NOT appear in these scripts. The Server only
// participates in the VTXO creation (cooperative path), not in Lightning
// operations.
//
// This is inspired by the Arkade go-sdk lightning_channel_scripts example:
// https://github.com/tiero/go-sdk/blob/master/example/lightning_channel_scripts/main.go
type LightningChannelScriptBuilder struct {
	// AliceKey is one channel participant's public key.
	AliceKey *btcec.PublicKey

	// BobKey is the other channel participant's public key.
	BobKey *btcec.PublicKey

	// ExitDelay is the CSV delay for unilateral exit.
	ExitDelay RelativeLocktime
}

// NewLightningChannelScriptBuilder creates a new Lightning channel script
// builder.
//
// Parameters:
//   - aliceKey: Public key of first channel participant
//   - bobKey: Public key of second channel participant
//   - exitDelay: CSV delay for unilateral exit
//
// The resulting scripts create a 2-of-2 multisig channel between Alice and
// Bob, with an Ark timeout escape hatch for unilateral exit.
func NewLightningChannelScriptBuilder(aliceKey, bobKey *btcec.PublicKey,
	exitDelay RelativeLocktime) *LightningChannelScriptBuilder {

	return &LightningChannelScriptBuilder{
		AliceKey:  aliceKey,
		BobKey:    bobKey,
		ExitDelay: exitDelay,
	}
}

// BuildLightning2of2Script creates the standard Lightning 2-of-2 multisig
// script using Tapscript (BIP342).
//
// Script: OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
//
// This is a standard BIP342 Tapscript that requires signatures from both
// Alice and Bob to spend.
func (l *LightningChannelScriptBuilder) BuildLightning2of2Script() ([]byte, error) {
	builder := txscript.NewScriptBuilder()

	// Alice's signature check
	builder.AddData(schnorr.SerializePubKey(l.AliceKey))
	builder.AddOp(txscript.OP_CHECKSIG)

	// Bob's signature check and accumulate
	builder.AddData(schnorr.SerializePubKey(l.BobKey))
	builder.AddOp(txscript.OP_CHECKSIGADD)

	// Require exactly 2 valid signatures
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_NUMEQUAL)

	return builder.Script()
}

// BuildLightningScriptWithCSV adds a CSV timeout to the Lightning script.
//
// This creates: <lightning_script> OP_CSV(<delay>)
//
// The CSV delay enables unilateral exit if the Arkade Server becomes
// unavailable. This should NEVER be needed during normal Lightning operation.
func (l *LightningChannelScriptBuilder) BuildLightningScriptWithCSV(
	lightningScript []byte) ([]byte, error) {

	// Convert exit delay to CSV sequence
	csvSequence, err := l.ExitDelay.Sequence()
	if err != nil {
		return nil, fmt.Errorf("failed to convert exit delay to "+
			"CSV sequence: %w", err)
	}

	builder := txscript.NewScriptBuilder()

	// Add the original Lightning script as raw opcodes
	builder.AddOps(lightningScript)

	// Add CSV timeout
	builder.AddInt64(int64(csvSequence))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)

	return builder.Script()
}

// BuildDualPathChannelScripts creates the dual-path Taproot structure for
// Lightning channel funding outputs.
//
// Returns:
//   - lightningScript: Standard 2-of-2 multisig for normal operation
//   - csvScript: Same multisig + CSV timeout for unilateral exit
//   - error: Any error encountered
func (l *LightningChannelScriptBuilder) BuildDualPathChannelScripts() (
	lightningScript, csvScript []byte, err error) {

	// Standard Lightning 2-of-2 multisig script
	lightningScript, err = l.BuildLightning2of2Script()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build Lightning "+
			"script: %w", err)
	}

	// Lightning script + CSV timeout for Ark unilateral exit
	csvScript, err = l.BuildLightningScriptWithCSV(lightningScript)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build CSV script: %w", err)
	}

	return lightningScript, csvScript, nil
}

// ArkadeState represents the state of the Arkade funding intent.
type ArkadeState uint8

const (
	// ArkadeStateInit indicates the intent has been created but funding
	// has not started.
	ArkadeStateInit ArkadeState = iota

	// ArkadeStateOutputKnown indicates the funding output parameters
	// are known and funding can proceed.
	ArkadeStateOutputKnown

	// ArkadeStateFundingCreated indicates the funding transaction has
	// been created but not yet signed.
	ArkadeStateFundingCreated

	// ArkadeStateFundingSigned indicates the funding transaction has
	// been signed by the Arkade Server.
	ArkadeStateFundingSigned

	// ArkadeStateComplete indicates the funding process is complete.
	ArkadeStateComplete

	// ArkadeStateCanceled indicates the funding intent was canceled.
	ArkadeStateCanceled
)

// String returns a human-readable string representation of ArkadeState.
func (s ArkadeState) String() string {
	switch s {
	case ArkadeStateInit:
		return "init"
	case ArkadeStateOutputKnown:
		return "output_known"
	case ArkadeStateFundingCreated:
		return "funding_created"
	case ArkadeStateFundingSigned:
		return "funding_signed"
	case ArkadeStateComplete:
		return "complete"
	case ArkadeStateCanceled:
		return "canceled"
	default:
		return fmt.Sprintf("<unknown(%d)>", s)
	}
}

// ArkadeIntent is an intent created by the ArkadeAssembler which represents
// a funding output to be created using Arkade VTXOs. This allows users to
// fund Lightning channels using their off-chain Ark balance instead of
// on-chain UTXOs.
type ArkadeIntent struct {
	// ShimIntent contains the common funding intent fields.
	ShimIntent

	// State is the current state of the Arkade funding intent.
	State ArkadeState

	// client is the Arkade client used to communicate with the Arkade Server.
	client ArkadeClient

	// fundingTx is the funding transaction created by the Arkade Server.
	fundingTx *wire.MsgTx

	// selectedVTXOs are the VTXOs selected to fund the channel.
	selectedVTXOs []VTXO

	// netParams are the network parameters.
	netParams *chaincfg.Params

	// ArkadeReady is a channel that signals when the Arkade funding
	// process is complete. In the happy path, this channel is closed.
	// If an error occurs, the error is sent through this channel.
	//
	// NOTE: This channel must always be buffered.
	ArkadeReady chan error

	// signalReady is a Once guard to ensure ArkadeReady is only closed once.
	signalReady sync.Once

	// mu protects concurrent access to the intent's state.
	mu sync.RWMutex
}

// BindKeys sets both the remote and local node's keys that will be used for
// the channel funding multisig output.
func (i *ArkadeIntent) BindKeys(localKey *keychain.KeyDescriptor,
	remoteKey *btcec.PublicKey) {

	i.mu.Lock()
	defer i.mu.Unlock()

	i.localKey = localKey
	i.remoteKey = remoteKey
	i.State = ArkadeStateOutputKnown
}

// CreateFundingTx creates the funding transaction by selecting VTXOs and
// requesting the Arkade Server to create a transaction that funds the channel.
func (i *ArkadeIntent) CreateFundingTx(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.State != ArkadeStateOutputKnown {
		return fmt.Errorf("invalid state: got %v, expected %v",
			i.State, ArkadeStateOutputKnown)
	}

	if i.client == nil {
		return ErrArkadeNotConfigured
	}

	// Check Arkade Server availability.
	if !i.client.IsAvailable(ctx) {
		return ErrArkadeServerUnavailable
	}

	// Get the funding output to determine the address.
	_, txOut, err := i.FundingOutput()
	if err != nil {
		return fmt.Errorf("unable to create funding output: %w", err)
	}

	// Parse the funding script to get the address.
	fundingAddr, err := btcutil.NewAddressWitnessScriptHash(
		txOut.PkScript[2:], i.netParams,
	)
	if err != nil {
		return fmt.Errorf("unable to parse funding address: %w", err)
	}

	// Check that we have sufficient VTXO balance.
	balance, err := i.client.GetVTXOBalance(ctx)
	if err != nil {
		return fmt.Errorf("unable to get VTXO balance: %w", err)
	}

	fundingAmt := i.localFundingAmt + i.remoteFundingAmt
	if balance < fundingAmt {
		return fmt.Errorf("%w: have %v, need %v",
			ErrInsufficientVTXOBalance, balance, fundingAmt)
	}

	// Request the Arkade Server to create the funding transaction.
	tx, err := i.client.CreateFundingTransaction(ctx, fundingAddr, fundingAmt)
	if err != nil {
		return fmt.Errorf("unable to create funding tx: %w", err)
	}

	i.fundingTx = tx
	i.State = ArkadeStateFundingCreated

	return nil
}

// SignFundingTx requests the Arkade Server to sign the funding transaction.
func (i *ArkadeIntent) SignFundingTx(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.State != ArkadeStateFundingCreated {
		return fmt.Errorf("invalid state: got %v, expected %v",
			i.State, ArkadeStateFundingCreated)
	}

	if i.client == nil {
		return ErrArkadeNotConfigured
	}

	// Request the Arkade Server to sign the funding transaction.
	signedTx, err := i.client.SignFundingTransaction(ctx, i.fundingTx)
	if err != nil {
		return fmt.Errorf("unable to sign funding tx: %w", err)
	}

	i.fundingTx = signedTx
	i.State = ArkadeStateFundingSigned

	return nil
}

// CompileFundingTx returns the signed funding transaction and sets the
// channel point.
func (i *ArkadeIntent) CompileFundingTx() (*wire.MsgTx, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.State != ArkadeStateFundingSigned {
		return nil, fmt.Errorf("invalid state: got %v, expected %v",
			i.State, ArkadeStateFundingSigned)
	}

	// Find the funding output in the transaction.
	_, txOut, err := i.FundingOutput()
	if err != nil {
		return nil, fmt.Errorf("unable to get funding output: %w", err)
	}

	var fundingIdx uint32
	found := false
	for idx, out := range i.fundingTx.TxOut {
		if out.Value == txOut.Value &&
			string(out.PkScript) == string(txOut.PkScript) {
			fundingIdx = uint32(idx)
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("funding output not found in tx")
	}

	i.chanPoint = &wire.OutPoint{
		Hash:  i.fundingTx.TxHash(),
		Index: fundingIdx,
	}
	i.State = ArkadeStateComplete

	// Signal that funding is complete.
	i.signalReady.Do(func() {
		close(i.ArkadeReady)
	})

	return i.fundingTx, nil
}

// Cancel cancels the Arkade funding intent.
//
// NOTE: This method satisfies the chanfunding.Intent interface.
func (i *ArkadeIntent) Cancel() {
	i.mu.Lock()
	defer i.mu.Unlock()

	log.Debugf("Arkade funding intent canceled, state=%v", i.State)

	i.signalReady.Do(func() {
		i.ArkadeReady <- ErrArkadeIntentCanceled
		i.State = ArkadeStateCanceled
	})

	i.ShimIntent.Cancel()
}

// Inputs returns all inputs to the funding transaction.
func (i *ArkadeIntent) Inputs() []wire.OutPoint {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.fundingTx == nil {
		return nil
	}

	inputs := make([]wire.OutPoint, 0, len(i.fundingTx.TxIn))
	for _, in := range i.fundingTx.TxIn {
		inputs = append(inputs, in.PreviousOutPoint)
	}

	return inputs
}

// Outputs returns all outputs of the funding transaction.
func (i *ArkadeIntent) Outputs() []*wire.TxOut {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.fundingTx == nil {
		return nil
	}

	return i.fundingTx.TxOut
}

// A compile-time check to ensure ArkadeIntent adheres to the Intent interface.
var _ Intent = (*ArkadeIntent)(nil)

// ArkadeAssembler is a type of chanfunding.Assembler that uses Arkade VTXOs
// to fund Lightning channels. This allows users to open channels using their
// off-chain Ark balance instead of on-chain UTXOs, providing faster and
// cheaper channel opens.
type ArkadeAssembler struct {
	// fundingAmt is the total amount of coins in the funding output.
	fundingAmt btcutil.Amount

	// client is the Arkade client used to communicate with the Arkade Server.
	client ArkadeClient

	// netParams are the network parameters.
	netParams *chaincfg.Params

	// shouldPublish indicates if the funding transaction should be
	// published after channel negotiation completes.
	shouldPublish bool
}

// NewArkadeAssembler creates a new ArkadeAssembler with the given parameters.
func NewArkadeAssembler(fundingAmt btcutil.Amount, client ArkadeClient,
	netParams *chaincfg.Params, shouldPublish bool) *ArkadeAssembler {

	return &ArkadeAssembler{
		fundingAmt:    fundingAmt,
		client:        client,
		netParams:     netParams,
		shouldPublish: shouldPublish,
	}
}

// ProvisionChannel creates a new ArkadeIntent given the passed funding Request.
//
// NOTE: This method satisfies the chanfunding.Assembler interface.
func (a *ArkadeAssembler) ProvisionChannel(req *Request) (Intent, error) {
	// SubtractFees is not supported for Arkade funding as the transaction
	// is assembled by the Arkade Server.
	if req.SubtractFees {
		return nil, fmt.Errorf("SubtractFees not supported for " +
			"Arkade funding")
	}

	// FundUpToMaxAmt and MinFundAmt are not supported as the funding amount
	// must be specified explicitly.
	if req.FundUpToMaxAmt != 0 || req.MinFundAmt != 0 {
		return nil, fmt.Errorf("FundUpToMaxAmt and MinFundAmt not " +
			"supported for Arkade funding")
	}

	if a.client == nil {
		return nil, ErrArkadeNotConfigured
	}

	intent := &ArkadeIntent{
		ShimIntent: ShimIntent{
			localFundingAmt: a.fundingAmt,
			musig2:          req.Musig2,
			tapscriptRoot:   req.TapscriptRoot,
		},
		State:       ArkadeStateInit,
		client:      a.client,
		netParams:   a.netParams,
		ArkadeReady: make(chan error, 1),
	}

	// Validate that the request amounts match the assembler's funding amount.
	if req.LocalAmt+req.RemoteAmt != a.fundingAmt {
		return nil, fmt.Errorf("intent doesn't match Arkade "+
			"assembler: local_amt=%v, remote_amt=%v, funding_amt=%v",
			req.LocalAmt, req.RemoteAmt, a.fundingAmt)
	}

	return intent, nil
}

// ShouldPublishFundingTx returns whether the funding transaction should be
// published after channel negotiations complete.
//
// NOTE: This method is part of the ConditionalPublishAssembler interface.
func (a *ArkadeAssembler) ShouldPublishFundingTx() bool {
	return a.shouldPublish
}

// FundingTxAvailable signals that this assembler can provide the funding
// transaction.
//
// NOTE: This method is part of the FundingTxAssembler interface.
func (a *ArkadeAssembler) FundingTxAvailable() {}

// A compile-time assertion to ensure ArkadeAssembler meets the
// ConditionalPublishAssembler interface.
var _ ConditionalPublishAssembler = (*ArkadeAssembler)(nil)

// A compile-time assertion to ensure ArkadeAssembler meets the
// FundingTxAssembler interface.
var _ FundingTxAssembler = (*ArkadeAssembler)(nil)
