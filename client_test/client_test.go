package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	// "fmt"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const defaultPassword1 = "Mangoesareyummy"
const incorrectPassword = "notpassword"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = " Please"
const contentFive = " Work"
const contentSix = " I beg."

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Test InitUser Errors.", func() {
			userlib.DebugMsg("Checking that an empty username is not initialized.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that a second user Alice is not initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that user Alice (capital) is initialized and case-sensitive.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking user Bob is initialized with same password as Alice.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Test GetUser Errors.", func() {
			userlib.DebugMsg("Checking user Alice is not recieved before initialization.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking user Alice is recieved with correct password.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking user Alice is not recieved with correct password.")
			alice, err = client.GetUser("alice", incorrectPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Datastore Integrity Test: Testing GetUser Integrity.", func() {
			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that tampering with user Alice is detected.")
			usernameHash := userlib.Hash([]byte("alice"))
			usernameUUID, _ := uuid.FromBytes(usernameHash[:16])
			userlib.DatastoreSet(usernameUUID, []byte("garbage"))

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that user Bob is initialized.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that user Bob is recieved.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that tampering with user Bob is detected with HMAC.")
			usernameHash = userlib.Hash([]byte("bob"))
			usernameUUID, _ = uuid.FromBytes(usernameHash[:16])
			ftext, _ := userlib.DatastoreGet(usernameUUID)
			testhmac := ftext[len(ftext)-64:]
			ciphertext := []byte("garbage")
			totalLength := len(ciphertext) + len(testhmac)
			finaltext := make([]byte, totalLength)
			copy(finaltext, ciphertext)
			copy(finaltext[len(ciphertext):], testhmac)
			userlib.DatastoreSet(usernameUUID, finaltext)

			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Test Store/Load File Errors.", func() {
			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Basic Test: Test Append File Errors.", func() {
			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("In-Depth Test: Test Store/Load/Append File Functionality.", func() {
			userlib.DebugMsg("Checking that user Alice is initialized.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Storing file data: %s", contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentTwo + contentOne)))
		})

		Specify("Basic Test: Clear Datastore.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Loading a file")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("In-Depth Test: Testing Revoke Functionality Extensively", func() {

			userlib.DebugMsg("Initializing the users.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword1)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", defaultPassword1)
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", defaultPassword1)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating the files.")
			alice.StoreFile(aliceFile, []byte(contentOne)) // shared with everyone
			alice.StoreFile("aliceFile2.txt", []byte(contentTwo)) // shared and revoked
			alice.StoreFile("aliceFile3.txt", []byte(contentThree)) // never shared
			bob.StoreFile(bobFile, []byte(contentFour)) // shared and revoked

			userlib.DebugMsg("Creating/accepting invitations.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, _ = alice.CreateInvitation("aliceFile2.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "alice2.txt")
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = alice.CreateInvitation("aliceFile2.txt", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Skip doris, he doesn't accept Charles's invite
			inviteDoris1, err := charles.CreateInvitation("alice1.txt", "doris")
			Expect(err).To(BeNil())
			inviteDoris2, err := charles.CreateInvitation("alice2.txt", "doris")
			Expect(err).To(BeNil())

			// Bob invites Eve
			invite, err = bob.CreateInvitation("alice1.txt", "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("bob", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation("alice2.txt", "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("bob", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Bob invites Frank
			invite, err = bob.CreateInvitation("alice1.txt", "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("bob", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation("alice2.txt", "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("bob", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Charles invites Grace
			invite, err = charles.CreateInvitation("alice1.txt", "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("charles", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation("alice2.txt", "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("charles", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Charles invites Horace
			invite, err = charles.CreateInvitation("alice1.txt", "horace")
			Expect(err).To(BeNil())
			err = horace.AcceptInvitation("charles", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation("alice2.txt", "horace")
			Expect(err).To(BeNil())
			err = horace.AcceptInvitation("charles", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Horace invites Ira
			invite, err = horace.CreateInvitation("alice1.txt", "ira")
			Expect(err).To(BeNil())
			err = ira.AcceptInvitation("horace", invite, "alice1.txt")
			Expect(err).To(BeNil())
			invite, err = horace.CreateInvitation("alice2.txt", "ira")
			Expect(err).To(BeNil())
			err = ira.AcceptInvitation("horace", invite, "alice2.txt")
			Expect(err).To(BeNil())

			// Revoke the accesses for Bob
			err = alice.RevokeAccess("aliceFile2.txt", "charles")
			Expect(err).To(BeNil())

			// Check that all the access changes
			userlib.DebugMsg("Checking Bob functionality.")
			data, err := bob.LoadFile("alice1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			_, err = bob.LoadFile("alice2.txt")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			err = bob.AppendToFile("alice1.txt", []byte(contentFive))
			Expect(err).To(BeNil())
			data, err = bob.LoadFile("alice1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentFive)))
			_, err = bob.LoadFile("alice2.txt")
			err = bob.AppendToFile("alice2.txt", []byte(contentSix))
			Expect(err).To(BeNil())
			err = bob.AppendToFile(bobFile, []byte(contentSix))
			Expect(err).To(BeNil())
			_, err = bob.CreateInvitation("alice1.txt", "doris")
			Expect(err).To(BeNil())
			_, err = bob.CreateInvitation("alice2.txt", "doris")
			Expect(err).To(BeNil())
			_, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking Charles functionality.")
			data, err = charles.LoadFile("alice1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentFive)))
			_, err = charles.LoadFile("alice2.txt")
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile("alice1.txt", []byte(contentSix))
			Expect(err).To(BeNil())
			data, err = charles.LoadFile("alice1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentFive + contentSix)))
			err = charles.AppendToFile("alice2.txt", []byte(contentSix))
			Expect(err).ToNot(BeNil())
			data, err = charles.LoadFile("alice2.txt")
			Expect(err).ToNot(BeNil())
			_, err = charles.CreateInvitation("alice1.txt", "doris")
			Expect(err).To(BeNil())
			_, err = charles.CreateInvitation("alice2.txt", "doris")
			Expect(err).ToNot(BeNil())

			err = doris.AcceptInvitation("charles", inviteDoris1, "alice1.txt")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("charles", inviteDoris2, "alice2.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("Datastore Map Test: Testing Copy Paste Attack Vulnerability.", func() {
			charles, err = client.InitUser("charles", defaultPassword1)
			_ = charles.StoreFile(charlesFile, []byte("AAAA"))
			datastoreMap := userlib.DatastoreGetMap()
			allKeys := make([]uuid.UUID, 0, len(datastoreMap))
			for key := range datastoreMap {
				allKeys = append(allKeys, key)
			}
			_ = charles.AppendToFile(charlesFile, []byte("BBBB"))
			new_val := []byte("")
			for key, value := range datastoreMap {
				found := false
				for _, k := range allKeys {
					if k == key {
						found = true
						break
					}
				}
				if !found {
					new_val = value
					break
				}
			}
			allKeys = make([]uuid.UUID, 0, len(datastoreMap))
			for key := range datastoreMap {
				allKeys = append(allKeys, key)
			}
			_ = charles.AppendToFile(charlesFile, []byte("CCCC"))
			for key, _ := range datastoreMap {
				found := false
				for _, k := range allKeys {
					if k == key {
						found = true
						break
					}
				}
				if !found {
					userlib.DatastoreSet(key, new_val)
				}
			}
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Datastore Map Test: Testing Authenticity.", func() {
			bob, err = client.InitUser("bob", defaultPassword1)
			datastoreMap := userlib.DatastoreGetMap()
			allKeys := make([]uuid.UUID, 0, len(datastoreMap))
			for key := range datastoreMap {
				allKeys = append(allKeys, key)
			}
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			for key, value := range datastoreMap {
				found := false
				for _, k := range allKeys {
					if k == key {
						found = true
						break
					}
				}
				if !found {
					userlib.DatastoreSet(key, append(value, "garbage"...))
				}
			}
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			datastoreMap = userlib.DatastoreGetMap()
			for key, value := range datastoreMap {
				userlib.DatastoreSet(key, append(value, "garbage"...))
			}
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})
})
