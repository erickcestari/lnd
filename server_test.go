package lnd

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/channels"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/stretchr/testify/require"
)

// TestNodeAnnouncementTimestampComparison tests the timestamp comparison
// logic used in setSelfNode to ensure node announcements have strictly
// increasing timestamps at second precision (as required by BOLT-07 and
// enforced by the database storage).
func TestNodeAnnouncementTimestampComparison(t *testing.T) {
	t.Parallel()

	// Use a simple base time for the tests.
	baseTime := int64(1000)

	tests := []struct {
		name              string
		srcNodeLastUpdate time.Time
		nodeLastUpdate    time.Time
		expectedResult    time.Time
		description       string
	}{
		{
			name:              "same second different nanoseconds",
			srcNodeLastUpdate: time.Unix(baseTime, 0),
			nodeLastUpdate:    time.Unix(baseTime, 500_000_000),
			expectedResult:    time.Unix(baseTime+1, 0),
			description: "Edge case: timestamps in same second " +
				"but different nanoseconds. Must increment " +
				"to avoid persisting same second-level " +
				"timestamp.",
		},
		{
			name:              "different seconds",
			srcNodeLastUpdate: time.Unix(baseTime, 0),
			nodeLastUpdate:    time.Unix(baseTime+2, 0),
			expectedResult:    time.Unix(baseTime+2, 0),
			description: "Normal case: current time is already " +
				"in a different (later) second. No increment " +
				"needed.",
		},
		{
			name:              "exactly equal",
			srcNodeLastUpdate: time.Unix(baseTime, 123456789),
			nodeLastUpdate:    time.Unix(baseTime, 123456789),
			expectedResult:    time.Unix(baseTime+1, 123456789),
			description: "Timestamps are identical. Must " +
				"increment to ensure strictly greater " +
				"timestamp.",
		},
		{
			name:              "exactly equal - zero nanoseconds",
			srcNodeLastUpdate: time.Unix(baseTime, 0),
			nodeLastUpdate:    time.Unix(baseTime, 0),
			expectedResult:    time.Unix(baseTime+1, 0),
			description: "Timestamps are identical at second " +
				"precision (0 nanoseconds), as would be read " +
				"from DB. Must increment.",
		},
		{
			name:              "clock skew - persisted is newer",
			srcNodeLastUpdate: time.Unix(baseTime+5, 0),
			nodeLastUpdate:    time.Unix(baseTime+3, 0),
			expectedResult:    time.Unix(baseTime+6, 0),
			description: "Clock went backwards: persisted " +
				"timestamp is newer than current time. Must " +
				"increment from persisted timestamp.",
		},
		{
			name:              "clock skew - same second",
			srcNodeLastUpdate: time.Unix(baseTime+5, 100_000_000),
			nodeLastUpdate:    time.Unix(baseTime+5, 900_000_000),
			expectedResult:    time.Unix(baseTime+6, 100_000_000),
			description: "Clock skew within same second. Must " +
				"increment to ensure strictly greater " +
				"second-level timestamp.",
		},
		{
			name: "same second component different " +
				"minute",
			srcNodeLastUpdate: time.Unix(baseTime, 0),
			nodeLastUpdate:    time.Unix(baseTime+60, 0),
			expectedResult:    time.Unix(baseTime+60, 0),
			description: "Same seconds component (:00) but " +
				"different minutes. Current time is later. " +
				"Verifies we use .Unix() not .Second().",
		},
		{
			name: "lower second component but " +
				"later time",
			srcNodeLastUpdate: time.Unix(baseTime+58, 0),
			nodeLastUpdate:    time.Unix(baseTime+63, 0),
			expectedResult:    time.Unix(baseTime+63, 0),
			description: "Persisted has second=58, current has " +
				"second=3 (next minute). Current is later " +
				"overall. Verifies .Unix() not .Second().",
		},
		{
			name: "higher second component but " +
				"earlier time",
			srcNodeLastUpdate: time.Unix(baseTime+63, 0),
			nodeLastUpdate:    time.Unix(baseTime+58, 0),
			expectedResult:    time.Unix(baseTime+64, 0),
			description: "Persisted has second=3 (next minute), " +
				"current has second=58. Persisted is later " +
				"overall. Verifies .Unix() not .Second().",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := calculateNodeAnnouncementTimestamp(
				tc.srcNodeLastUpdate,
				tc.nodeLastUpdate,
			)

			// Verify we got the expected result.
			require.Equal(
				t, tc.expectedResult, result,
				"Unexpected result: %s", tc.description,
			)

			// Verify result is strictly greater than persisted
			// timestamp. This is an additional check to ensure
			// the result is strictly greater than the persisted
			// timestamp.
			require.Greater(
				t, result.Unix(), tc.srcNodeLastUpdate.Unix(),
				"Result must be strictly greater than "+
					"persisted timestamp: %s",
				tc.description,
			)
		})
	}
}

// createTestOpenChannel creates a minimal open channel in the database for
// testing findChannel.
func createTestOpenChannel(t *testing.T, cdb *channeldb.ChannelStateDB,
	identityPub *btcec.PublicKey, fundingOutpoint wire.OutPoint,
	shortChanID lnwire.ShortChannelID) {

	t.Helper()

	producer, err := shachain.NewRevocationProducerFromBytes(
		bytes.Repeat([]byte{0xab}, 32),
	)
	require.NoError(t, err)

	store := shachain.NewRevocationStore()
	preImage, err := producer.AtIndex(0)
	require.NoError(t, err)
	require.NoError(t, store.AddNextEntry(preImage))

	keyCfg := channeldb.ChannelConfig{
		ChannelStateBounds: channeldb.ChannelStateBounds{
			MaxPendingAmount: 100000,
			ChanReserve:      5000,
			MinHTLC:          1,
			MaxAcceptedHtlcs: 30,
		},
		CommitmentParams: channeldb.CommitmentParams{
			DustLimit: 354,
			CsvDelay:  144,
		},
		MultiSigKey: keychain.KeyDescriptor{
			PubKey: identityPub},
		RevocationBasePoint: keychain.KeyDescriptor{
			PubKey: identityPub},
		PaymentBasePoint: keychain.KeyDescriptor{
			PubKey: identityPub},
		DelayBasePoint: keychain.KeyDescriptor{
			PubKey: identityPub},
		HtlcBasePoint: keychain.KeyDescriptor{
			PubKey: identityPub},
	}

	channel := &channeldb.OpenChannel{
		ChanType:        channeldb.SingleFunderBit,
		FundingOutpoint: fundingOutpoint,
		ShortChannelID:  shortChanID,
		IsInitiator:     true,
		IsPending:       true,
		IdentityPub:     identityPub,
		Capacity:        btcutil.Amount(1_000_000),
		LocalChanCfg:    keyCfg,
		RemoteChanCfg:   keyCfg,
		LocalCommitment: channeldb.ChannelCommitment{
			CommitTx:  channels.TestFundingTx,
			CommitSig: bytes.Repeat([]byte{1}, 71),
		},
		RemoteCommitment: channeldb.ChannelCommitment{
			CommitTx:  channels.TestFundingTx,
			CommitSig: bytes.Repeat([]byte{1}, 71),
		},
		NumConfsRequired:        3,
		RemoteCurrentRevocation: identityPub,
		RemoteNextRevocation:    identityPub,
		RevocationProducer:      producer,
		RevocationStore:         store,
		Db:                      cdb,
		Packager: channeldb.NewChannelPackager(
			shortChanID),
		FundingTxn: channels.TestFundingTx,
	}

	addr, _ := net.ResolveTCPAddr("tcp", "10.0.0.1:9735")
	require.NoError(t, channel.SyncPending(addr, 100))
	require.NoError(t, channel.MarkAsOpen(shortChanID))
}

// TestFindChannel is a regression test for server.findChannel. It verifies
// that findChannel correctly looks up a channel by ChannelID and rejects
// channels that don't belong to the expected peer.
func TestFindChannel(t *testing.T) {
	t.Parallel()

	fullDB := channeldb.OpenForTesting(t, t.TempDir())
	cdb := fullDB.ChannelStateDB()

	s := &server{
		chanStateDB: cdb,
	}

	// Create two distinct key pairs representing two different peers.
	alicePriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	alicePub := alicePriv.PubKey()

	bobPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPub := bobPriv.PubKey()

	// Create a channel belonging to Alice.
	aliceOutpoint := wire.OutPoint{
		Hash:  [32]byte{0x01},
		Index: 0,
	}
	aliceSCID := lnwire.NewShortChanIDFromInt(1)
	createTestOpenChannel(t, cdb, alicePub, aliceOutpoint, aliceSCID)

	chanID := lnwire.NewChanIDFromOutPoint(aliceOutpoint)

	// Test 1: findChannel with the correct node key should succeed.
	channel, err := s.findChannel(alicePub, chanID)
	require.NoError(t, err)
	require.True(t, channel.IdentityPub.IsEqual(alicePub))

	// Test 2: findChannel with a different node key should fail.
	// FetchChannelByID finds the channel but the pubkey check rejects it.
	_, err = s.findChannel(bobPub, chanID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not belong to")

	// Test 3: findChannel with a non-existent channel ID should fail.
	unknownOutpoint := wire.OutPoint{
		Hash:  [32]byte{0xff},
		Index: 99,
	}
	unknownChanID := lnwire.NewChanIDFromOutPoint(unknownOutpoint)
	_, err = s.findChannel(alicePub, unknownChanID)
	require.Error(t, err)
}
