package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	// "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	DecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	FileNodeMapUUID uuid.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type NodeKey struct {
	FileNodeID uuid.UUID
	SourceKey []byte
}

type FileNode struct{
	Owner bool
	FileHeaderUUID uuid.UUID
	SymKey []byte
	HMACKey []byte
	UsernameToFileNode map[string]NodeKey
}

type FileHeader struct {
	HeadUUID uuid.UUID
	TailUUID uuid.UUID
}

type FileSegment struct {
	NextUUID uuid.UUID
	ContentUUID uuid.UUID
}

type Invitation struct {
	SharedNodeUUID uuid.UUID
	SourceKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.FileNodeMapUUID = uuid.New()

	// Check if username is valid
	if len(username) < 1 {
		return &userdata, errors.New("Invalid username")
	}

	// Create deterministic UUID
	usernameHash := userlib.Hash([]byte(username))
	uuidUser, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return &userdata, err
	}

	// Check if username already exists
	_, ok := userlib.DatastoreGet(uuidUser)
	if (ok) {
		return &userdata, errors.New("Username already exists")
	}

	// Public encryption and private decryption keys
	var ek userlib.PKEEncKey
	var dk userlib.PKEDecKey
	ek, dk, _ = userlib.PKEKeyGen()
	err = userlib.KeystoreSet(username+"Enc", ek)
	userdata.DecKey = dk

	// Public verification and private signing keys
	var vk userlib.DSVerifyKey
	var sk userlib.DSSignKey
	sk, vk, _ = userlib.DSKeyGen()
	err = userlib.KeystoreSet(username+"Ver", vk)
	userdata.SignKey = sk

	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return &userdata, err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return &userdata, err
	}

	// Creating a FileMap
	// Marshalling and encrypting File Node Map
	var plainMaptext []byte
	plainMaptext, err = json.Marshal(make(map[string]NodeKey))
	if err != nil {
		return &userdata, err
	}
	finalMapText, err:= EncMacHelper(encUser[:16], hmacUser[:16], plainMaptext)
	if err != nil {
		return &userdata, err
	}

	// Marshalling and encrypting user struct
	var plaintext []byte
	plaintext, err = json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}
	finaltext, err:= EncMacHelper(encUser[:16], hmacUser[:16], plaintext)
	if err != nil {
		return &userdata, err
	}

	// Storing user struct and file node map in database
	userlib.DatastoreSet(userdata.FileNodeMapUUID, finalMapText)
	userlib.DatastoreSet(uuidUser, finaltext)
	return &userdata, nil
}

func EncMacHelper(encUser []byte, hmacUser []byte, plaintext []byte) (finaltext []byte, err error) {
	// Creating iv
	var iv []byte
	iv = userlib.RandomBytes(16)

	// Encrypting user struct
	ciphertext := userlib.SymEnc(encUser[:16], iv, plaintext)

	// Adding an HMAC to the end of the ciphertext
	hmac, err := userlib.HMACEval(hmacUser[:16], ciphertext)
	if err != nil {
		return ciphertext, err
	}
	totalLength := len(ciphertext) + len(hmac)
	finalt := make([]byte, totalLength)
	copy(finalt, ciphertext)
	copy(finalt[len(ciphertext):], hmac)
	return finalt, nil
}

func MacDecHelper(decUser []byte, hmacUser []byte, finalt []byte) (plaintext []byte, err error) {
		// Check that length of text was not changed
		if (len(finalt) < 64) {
			return finalt, errors.New("User struct tampering detected")
		}
	
		// Splitting recieved byte array from Datastore 
		ciphertext := finalt[:len(finalt)-64]
		storedhmac := finalt[len(finalt)-64:]
	
		// Checking HMAC
		var calculatedhmac []byte
		calculatedhmac, err = userlib.HMACEval(hmacUser[:16], ciphertext)
		if err != nil {
			return finalt, err
		}
		checkHMAC := userlib.HMACEqual(calculatedhmac, storedhmac)
		if (!checkHMAC) {
			return finalt, errors.New("HMAC not equal")
		}

		// Decrypting user struct
		var plaint []byte
		plaint = userlib.SymDec(decUser[:16], ciphertext)
		return plaint, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Create source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Check if username is valid
	if len(username) < 1 {
		return &userdata, errors.New("Invalid username")
	}

	// Create deterministic UUID
	usernameHash := userlib.Hash([]byte(username))
	uuidUser, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return &userdata, err
	}

	// Check if username exists
	finaltext, ok := userlib.DatastoreGet(uuidUser)
	if (!ok) {
		return &userdata, errors.New("Username does not exist")
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return &userdata, err
	}

	// Create symmetric encryption key
	var decUser []byte
	decUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return &userdata, err
	}

	// Decrypting and check HMAC
	var plaintext []byte
	plaintext, err = MacDecHelper(decUser[:16], hmacUser[:16], finaltext)
	if err != nil {
		return &userdata, err
	}

	// Unmarshalling user struct
	err = json.Unmarshal(plaintext, userdataptr)
	if err != nil {
		return &userdata, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return errors.New("File Map was deleted")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return err
	}

	fileNodeKey, fileExists := fileMap[filename]

	// Case that this is a brand new file
	if (!fileExists) {
		var fileNode FileNode
		fileNode.SymKey = userlib.RandomBytes(16)
		fileNode.HMACKey = userlib.RandomBytes(16)
		fileNode.Owner = true
		fileNode.UsernameToFileNode = make(map[string]NodeKey)
		fileNodeUUID := uuid.New()
		fileHeaderUUID := uuid.New()
		fileSegmentUUID	:= uuid.New()
		fileContentUUID := uuid.New()
		var fileHeader FileHeader
		var fileSegment FileSegment
		fileSegment.NextUUID = uuid.Nil
		fileSegment.ContentUUID = fileContentUUID
		fileHeader.HeadUUID = fileSegmentUUID
		fileHeader.TailUUID = fileSegmentUUID
		fileNode.FileHeaderUUID = fileHeaderUUID
		// fileNode.UsernameToFileNode[userdata.Username] = fileNodeUUID
		var nodeKey NodeKey
		nodeKey.SourceKey = userlib.RandomBytes(16)
		nodeKey.FileNodeID = fileNodeUUID
		fileMap[filename] = nodeKey

		// Encrypting content
		var encryptedContent []byte
		encryptedContent, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, content)
		if err != nil {
			return err
		}

		// Marshalling and encrypting FileSegment struct
		var plainFileSegment []byte
		plainFileSegment, err = json.Marshal(fileSegment)
		if err != nil {
			return err
		}
		var encryptedFileSegment []byte
		encryptedFileSegment, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileSegment)
		if err != nil {
			return err
		}

		// Marshalling and encrypting FileHeader struct
		var plainFileHeader []byte
		plainFileHeader, err = json.Marshal(fileHeader)
		if err != nil {
			return err
		}
		var encryptedFileHeader []byte
		encryptedFileHeader, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileHeader)
		if err != nil {
			return err
		}

		// Marshalling and encrypting FileNode struct
		// Create root/source key
		// var sourceKeyNode []byte
		// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)

		// Create symmetric encryption key
		var encNode []byte
		encNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("encUser"))
		if err != nil {
			return err
		}

		// Create HMAC key
		var hmacNode []byte
		hmacNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("hmac"))
		if err != nil {
			return err
		}

		var plainFileNode []byte
		plainFileNode, err = json.Marshal(fileNode)
		if err != nil {
			return err
		}
		var encryptedFileNode []byte
		encryptedFileNode, err = EncMacHelper(encNode[:16], hmacNode[:16], plainFileNode)
		if err != nil {
			return err
		}

		// Storing everything in the Datastore
		userlib.DatastoreSet(fileContentUUID, encryptedContent)
		userlib.DatastoreSet(fileSegmentUUID, encryptedFileSegment)
		userlib.DatastoreSet(fileHeaderUUID, encryptedFileHeader)
		userlib.DatastoreSet(fileNodeUUID, encryptedFileNode)

		// Storing File Map back in Datastore
		// Marshalling, encrypting, and storing File Map
		var plainMapText []byte
		plainMapText, err = json.Marshal(fileMap)
		if err != nil {
			return err
		}
		finalMapText, err:= EncMacHelper(encUser[:16], hmacUser[:16], plainMapText)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(userdata.FileNodeMapUUID, finalMapText)

	} else {
		// Decrypting and Unmarshalling the FileNode struct
		finalNodeText, ok := userlib.DatastoreGet(fileNodeKey.FileNodeID)
		if (!ok) {
			return errors.New("File Node was deleted or unauthorized access")
		}

		// var sourceKeyNode []byte
		// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
		var decNode []byte
		decNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("encUser"))
		if err != nil {
			return err
		}
		var hmacNode []byte
		hmacNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("hmac"))
		if err != nil {
			return err
		}
		var plainNodeText []byte
		plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
		if err != nil {
			return err
		}
		var fileNode FileNode
		fileNodePtr := &fileNode
		err = json.Unmarshal(plainNodeText, fileNodePtr)
		if err != nil {
			return err
		}

		// Decrypting and Unmarshalling the FileHeader Struct
		finalHeaderText, ok := userlib.DatastoreGet(fileNode.FileHeaderUUID)
		if (!ok) {
			return errors.New("File Header was deleted")
		}
		var plainHeaderText []byte
		plainHeaderText, err = MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalHeaderText)
		if err != nil {
			return err
		}
		var fileHeader FileHeader
		fileHeaderPtr := &fileHeader
		err = json.Unmarshal(plainHeaderText, fileHeaderPtr)
		if err != nil {
			return err
		}

		// Loop through file segments and delete them all
		curUUID := fileHeader.HeadUUID
		for curUUID != uuid.Nil {
			// Decrypting and Unmarshalling the FileHeader Struct
			finalSegmentText, ok := userlib.DatastoreGet(curUUID)
			if (!ok) {
				return errors.New("File Segment was deleted")
			}
			var plainSegmentText []byte
			plainSegmentText, err = MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalSegmentText)
			if err != nil {
				return err
			}
			var fileSegment FileSegment
			fileSegmentPtr := &fileSegment
			err = json.Unmarshal(plainSegmentText, fileSegmentPtr)
			if err != nil {
				return err
			}

			// Delete content
			userlib.DatastoreDelete(fileSegment.ContentUUID)
			userlib.DatastoreDelete(curUUID)

			// Iterate to next File Segment
			curUUID = fileSegment.NextUUID
		}

		fileSegmentUUID	:= uuid.New()
		fileContentUUID := uuid.New()
		var newFileSegment FileSegment
		newFileSegment.NextUUID = uuid.Nil
		newFileSegment.ContentUUID = fileContentUUID
		fileHeader.HeadUUID = fileSegmentUUID
		fileHeader.TailUUID = fileSegmentUUID

		// Encrypting content
		var encryptedContent []byte
		encryptedContent, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, content)
		if err != nil {
			return err
		}

		// Marshalling and encrypting FileSegment struct
		var plainFileSegment []byte
		plainFileSegment, err = json.Marshal(newFileSegment)
		if err != nil {
			return err
		}
		var encryptedFileSegment []byte
		encryptedFileSegment, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileSegment)
		if err != nil {
			return err
		}

		// Marshalling and encrypting FileHeader struct
		var plainFileHeader []byte
		plainFileHeader, err = json.Marshal(fileHeader)
		if err != nil {
			return err
		}
		var encryptedFileHeader []byte
		encryptedFileHeader, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileHeader)
		if err != nil {
			return err
		}
		
		// Storing everything in the Datastore
		userlib.DatastoreSet(fileContentUUID, encryptedContent)
		userlib.DatastoreSet(fileSegmentUUID, encryptedFileSegment)
		userlib.DatastoreSet(fileNode.FileHeaderUUID, encryptedFileHeader)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var err error

	// Getting the FileMap
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return errors.New("File Map was deleted")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return err
	}

	fileNodeKey, fileExists := fileMap[filename]
	if !fileExists {
		return errors.New("File does not exist in this user's namespace")
	}

	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(fileNodeKey.FileNodeID)
	if (!ok) {
		return errors.New("File Node was deleted or unauthorized access")
	}
	// var sourceKeyNode []byte
	// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
	var decNode []byte
	decNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return err
	}

	// Decrypting and Unmarshalling the FileHeader Struct
	finalHeaderText, ok := userlib.DatastoreGet(fileNode.FileHeaderUUID)
	if (!ok) {
		return errors.New("File Header was deleted")
	}
	var plainHeaderText []byte
	plainHeaderText, err = MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalHeaderText)
	if err != nil {
		return err
	}
	var fileHeader FileHeader
	fileHeaderPtr := &fileHeader
	err = json.Unmarshal(plainHeaderText, fileHeaderPtr)
	if err != nil {
		return err
	}

	// Decrypting and Unmarshalling the Tail FileSegment Struct
	finalSegmentText, ok := userlib.DatastoreGet(fileHeader.TailUUID)
	if (!ok) {
		return errors.New("File Segment was deleted")
	}
	var plainSegmentText []byte
	plainSegmentText, err = MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalSegmentText)
	if err != nil {
		return err
	}
	var fileSegment FileSegment
	fileSegmentPtr := &fileSegment
	err = json.Unmarshal(plainSegmentText, fileSegmentPtr)
	if err != nil {
		return err
	}

	newFileSegmentUUID := uuid.New()
	newFileContentUUID := uuid.New()
	var newFileSegment FileSegment
	newFileSegment.NextUUID = uuid.Nil
	newFileSegment.ContentUUID = newFileContentUUID
	fileSegment.NextUUID = newFileSegmentUUID
	oldTailUUID := fileHeader.TailUUID
	fileHeader.TailUUID = newFileSegmentUUID

	// Encrypting content
	var encryptedContent []byte
	encryptedContent, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, content)
	if err != nil {
		return err
	}

	// Marshalling and encrypting FileSegment struct
	var plainFileSegment []byte
	plainFileSegment, err = json.Marshal(fileSegment)
	if err != nil {
		return err
	}
	var encryptedFileSegment []byte
	encryptedFileSegment, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileSegment)
	if err != nil {
		return err
	}

	// Marshalling and encrypting newFileSegment struct
	var plainNewFileSegment []byte
	plainNewFileSegment, err = json.Marshal(newFileSegment)
	if err != nil {
		return err
	}
	var encryptedNewFileSegment []byte
	encryptedNewFileSegment, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainNewFileSegment)
	if err != nil {
		return err
	}

	// Marshalling and encrypting FileHeader struct
	var plainFileHeader []byte
	plainFileHeader, err = json.Marshal(fileHeader)
	if err != nil {
		return err
	}
	var encryptedFileHeader []byte
	encryptedFileHeader, err = EncMacHelper(fileNode.SymKey, fileNode.HMACKey, plainFileHeader)
	if err != nil {
		return err
	}
	
	// Storing everything in the Datastore
	userlib.DatastoreSet(newFileContentUUID, encryptedContent)
	userlib.DatastoreSet(oldTailUUID, encryptedFileSegment)
	userlib.DatastoreSet(newFileSegmentUUID, encryptedNewFileSegment)
	userlib.DatastoreSet(fileNode.FileHeaderUUID, encryptedFileHeader)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Getting the FileMap
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return content, err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return content, err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return content, errors.New("File Map was deleted")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return content, err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return content, err
	}

	fileNodeKey, fileExists := fileMap[filename]
	if !fileExists {
		return content, errors.New("File does not exist in this user's namespace")
	}

	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(fileNodeKey.FileNodeID)
	if (!ok) {
		return content, errors.New("File Node was deleted or unauthorized access")
	}
	// var sourceKeyNode []byte
	// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
	var decNode []byte
	decNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return content, err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return content, err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return content, err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return content, err
	}

	// Decrypting and Unmarshalling the FileHeader Struct
	finalHeaderText, ok := userlib.DatastoreGet(fileNode.FileHeaderUUID)
	if (!ok) {
		return content, errors.New("File Header was deleted")
	}
	var plainHeaderText []byte
	plainHeaderText, err = MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalHeaderText)
	if err != nil {
		return content, err
	}
	var fileHeader FileHeader
	fileHeaderPtr := &fileHeader
	err = json.Unmarshal(plainHeaderText, fileHeaderPtr)
	if err != nil {
		return content, err
	}

	// Looping through all file segments for content
	var allByteArrays []byte
	curUUID := fileHeader.HeadUUID
	for curUUID != uuid.Nil {
		// Decrypting and Unmarshalling the FileSegment Struct
		finalSegmentText, ok := userlib.DatastoreGet(curUUID)
		if (!ok) {
			return content, errors.New("File Segment was deleted")
		}
		plainSegmentText, err := MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalSegmentText)
		if err != nil {
			return content, err
		}
		var fileSegment FileSegment
		fileSegmentPtr := &fileSegment
		err = json.Unmarshal(plainSegmentText, fileSegmentPtr)
		if err != nil {
			return content, err
		}

		// Decrypting and unmarshalling the Content
		finalContextText, ok := userlib.DatastoreGet(fileSegment.ContentUUID)
		if (!ok) {
			return content, errors.New("File Content was deleted")
		}
		contentText, err := MacDecHelper(fileNode.SymKey, fileNode.HMACKey, finalContextText)
		if err != nil {
			return content, err
		}

		// Appending content to the total byte array and setting up next File Segment UUID
		allByteArrays = append(allByteArrays, contentText...)
		curUUID = fileSegment.NextUUID
	}

	return allByteArrays, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Create deterministic UUID
	recipientHash := userlib.Hash([]byte(recipientUsername))
	uuidRecipient, err := uuid.FromBytes(recipientHash[:16])
	if err != nil {
		return invitationPtr, err
	}

	// Check if recipient exists
	_, ok := userlib.DatastoreGet(uuidRecipient)
	if (!ok) {
		return invitationPtr, errors.New("Recipient does not exist")
	}
	
	// Getting the FileMap
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return invitationPtr, err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return invitationPtr, err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return invitationPtr, errors.New("File Map was deleted")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return invitationPtr, err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return invitationPtr, err
	}

	fileNodeKey, fileExists := fileMap[filename]
	if !fileExists {
		return invitationPtr, errors.New("File does not exist in this user's namespace")
	}

	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(fileNodeKey.FileNodeID)
	if (!ok) {
		return invitationPtr, errors.New("File Node was deleted or unauthorized access")
	}
	// var sourceKeyNode []byte
	// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
	var decNode []byte
	decNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return invitationPtr, err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return invitationPtr, err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return invitationPtr, err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return invitationPtr, err
	}

	var sharedFileNode FileNode
	sharedFileNode.SymKey = fileNode.SymKey
	sharedFileNode.HMACKey = fileNode.HMACKey
	sharedFileNode.Owner = false
	sharedFileNode.UsernameToFileNode = make(map[string]NodeKey)
	sharedFileNodeUUID := uuid.New()
	sharedFileNode.FileHeaderUUID = fileNode.FileHeaderUUID
	var sharedNodeKey NodeKey
	sharedNodeKey.SourceKey = userlib.RandomBytes(16)
	sharedNodeKey.FileNodeID = sharedFileNodeUUID
	fileNode.UsernameToFileNode[recipientUsername] = sharedNodeKey

	// Marshalling and encrypting sharedFileNode struct
	// Create root/source key
	// var sourceKeyShared []byte
	// sourceKeyShared = userlib.Argon2Key([]byte(filename), []byte(recipientUsername), 16)

	// Create symmetric encryption key
	var encShared []byte
	encShared, err = userlib.HashKDF(sharedNodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return invitationPtr, err
	}

	// Create HMAC key
	var hmacShared []byte
	hmacShared, err = userlib.HashKDF(sharedNodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return invitationPtr, err
	}

	var plainFileShared []byte
	plainFileShared, err = json.Marshal(sharedFileNode)
	if err != nil {
		return invitationPtr, err
	}
	var encryptedFileShared []byte
	encryptedFileShared, err = EncMacHelper(encShared[:16], hmacShared[:16], plainFileShared)
	if err != nil {
		return invitationPtr, err
	}

	// Storing sharedFileNode struct in the Datastore
	userlib.DatastoreSet(sharedFileNodeUUID, encryptedFileShared)

	// Marshalling and encrypting FileNode struct
	var plainFileNode []byte
	plainFileNode, err = json.Marshal(fileNode)
	if err != nil {
		return invitationPtr, err
	}
	var encryptedFileNode []byte
	encryptedFileNode, err = EncMacHelper(decNode[:16], hmacNode[:16], plainFileNode)
	if err != nil {
		return invitationPtr, err
	}

	// Storing FileNode struct in the Datastore
	userlib.DatastoreSet(fileNodeKey.FileNodeID, encryptedFileNode)

	var invite Invitation
	invite.SharedNodeUUID = sharedFileNodeUUID
	invite.SourceKey = sharedNodeKey.SourceKey

	// Marshalling and encrypting Invitation struct
	var plainInvite []byte
	plainInvite, err = json.Marshal(invite)
	if err != nil {
		return invitationPtr, err
	}

	ek, ok := userlib.KeystoreGet(recipientUsername+"Enc")
	if (!ok) {
		return invitationPtr, errors.New("Recipient public key missing")
	}
	cipherInvite, err := userlib.PKEEnc(ek, plainInvite)
	if err != nil {
		return invitationPtr, err
	}

	inviteSig, err := userlib.DSSign(userdata.SignKey, cipherInvite)
	if err != nil {
		return invitationPtr, err
	}
	encryptedInvite := append(cipherInvite, inviteSig...)
	
	// Storing FileNode struct in the Datastore
	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, encryptedInvite)
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var err error
	
	// Getting the FileMap
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return errors.New("File Map was deleted")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return err
	}
	
	_, fileExists := fileMap[filename]
	if fileExists {
		return errors.New("File already exists in this user's namespace")
	}
	
	// Getting Invitation struct from Datastore
	finalInviteText, ok := userlib.DatastoreGet(invitationPtr)
	if (!ok) {
		return errors.New("Invitation was deleted, revoked, or does not exist")
	}

	// Splitting recieved byte array from Datastore 
	cipherInviteText := finalInviteText[:len(finalInviteText)-256]
	storedSig := finalInviteText[len(finalInviteText)-256:]

	vk, ok := userlib.KeystoreGet(senderUsername+"Ver")
	if (!ok) {
		return errors.New("Sender verify key missing")
	}
	err = userlib.DSVerify(vk, cipherInviteText, storedSig)
	if err != nil {
		return err
	}

	plainInviteText, err := userlib.PKEDec(userdata.DecKey, cipherInviteText)
	if err != nil {
		return err
	}

	var invite Invitation
	invitePtr := &invite
	err = json.Unmarshal(plainInviteText, invitePtr)
	if err != nil {
		return err
	}

	_, ok = userlib.DatastoreGet(invite.SharedNodeUUID)
	if (!ok) {
		return errors.New("Node was deleted or revoked")
	}

	// Update and store fileMap in Datastore
	var nodeKey NodeKey
	nodeKey.FileNodeID = invite.SharedNodeUUID
	nodeKey.SourceKey = invite.SourceKey
	fileMap[filename] = nodeKey
	// Marshalling, encrypting, and storing File Map
	plainMapText, err = json.Marshal(fileMap)
	if err != nil {
		return err
	}
	finalMapText, err = EncMacHelper(encUser[:16], hmacUser[:16], plainMapText)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.FileNodeMapUUID, finalMapText)
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	var err error

	// Getting the FileMap
	// Create root/source key
	var sourceKey []byte
	sourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Create symmetric encryption key
	var encUser []byte
	encUser, err = userlib.HashKDF(sourceKey, []byte("encUser"))
	if err != nil {
		return err
	}

	// Create HMAC key
	var hmacUser []byte
	hmacUser, err = userlib.HashKDF(sourceKey, []byte("hmac"))
	if err != nil {
		return err
	}

	finalMapText, ok := userlib.DatastoreGet(userdata.FileNodeMapUUID)
	if (!ok) {
		return errors.New("File Map was deleted or modified")
	}
	var plainMapText []byte
	plainMapText, err = MacDecHelper(encUser[:16], hmacUser[:16], finalMapText)
	if err != nil {
		return err
	}
	var fileMap map[string]NodeKey
	fileMapPtr := &fileMap
	err = json.Unmarshal(plainMapText, fileMapPtr)
	if err != nil {
		return err
	}

	fileNodeKey, fileExists := fileMap[filename]
	if !fileExists {
		return errors.New("File does not exist in this user's namespace")
	}

	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(fileNodeKey.FileNodeID)
	if (!ok) {
		return errors.New("File Node was deleted or unauthorized access")
	}
	// var sourceKeyNode []byte
	// sourceKeyNode = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
	var decNode []byte
	decNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(fileNodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return err
	}

	sharedNodeKey, recipientExists := fileNode.UsernameToFileNode[recipientUsername]
	if !recipientExists {
		return errors.New("File is not currently shared with recipient")
	}

	err = DeleteAll(sharedNodeKey)
	if err != nil {
		return errors.New("Delete all failed")
	}
	delete(fileNode.UsernameToFileNode, recipientUsername)

	// Store FileNode back
	// Marshalling and encrypting FileNode struct
	var plainFileNode []byte
	plainFileNode, err = json.Marshal(fileNode)
	if err != nil {
		return err
	}
	var encryptedFileNode []byte
	encryptedFileNode, err = EncMacHelper(decNode[:16], hmacNode[:16], plainFileNode)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileNodeKey.FileNodeID, encryptedFileNode)


	newSymKey := userlib.RandomBytes(16)
	newHMACKey := userlib.RandomBytes(16)
	newFileHeaderUUID := uuid.New()

	err = ReecryptFile(fileNode.FileHeaderUUID, fileNode.SymKey, fileNode.HMACKey, newSymKey, newHMACKey, newFileHeaderUUID)
	if err != nil {
		return errors.New("ReencryptFile failed")
	}
	err = ReKeyAll(fileNodeKey, newSymKey, newHMACKey, newFileHeaderUUID)
	if err != nil {
		return errors.New("ReKeyAll failed")
	}

	return nil
}

func ReecryptFile(oldFileHeaderUUID uuid.UUID, oldSymKey []byte, oldHMACKey []byte, newSymKey []byte, newHMACKey []byte, newFileHeaderUUID uuid.UUID) (err error) {
	// Decrypting and Unmarshalling the FileHeader Struct
	finalHeaderText, ok := userlib.DatastoreGet(oldFileHeaderUUID)
	if (!ok) {
		return errors.New("File Header was deleted")
	}
	var plainHeaderText []byte
	plainHeaderText, err = MacDecHelper(oldSymKey, oldHMACKey, finalHeaderText)
	if err != nil {
		return err
	}
	var fileHeader FileHeader
	fileHeaderPtr := &fileHeader
	err = json.Unmarshal(plainHeaderText, fileHeaderPtr)
	if err != nil {
		return err
	}

	// Looping through all file segments for content
	curSegmentUUID := uuid.New()
	curUUID := fileHeader.HeadUUID
	head := true
	for curUUID != uuid.Nil {
		// Decrypting and Unmarshalling the FileSegment Struct
		finalSegmentText, ok := userlib.DatastoreGet(curUUID)
		if (!ok) {
			return errors.New("File Segment was deleted")
		}
		plainSegmentText, err := MacDecHelper(oldSymKey, oldHMACKey, finalSegmentText)
		if err != nil {
			return err
		}
		var fileSegment FileSegment
		fileSegmentPtr := &fileSegment
		err = json.Unmarshal(plainSegmentText, fileSegmentPtr)
		if err != nil {
			return 	err
		}

		// Decrypting and unmarshalling the Content
		finalContextText, ok := userlib.DatastoreGet(fileSegment.ContentUUID)
		if (!ok) {
			return errors.New("File Content was deleted")
		}
		contentText, err := MacDecHelper(oldSymKey, oldHMACKey, finalContextText)
		if err != nil {
			return err
		}

		finalContextText, err = EncMacHelper(newSymKey, newHMACKey, contentText)
		if err != nil {
			return err
		}

		newContentUUID :=uuid.New()
		userlib.DatastoreSet(newContentUUID, finalContextText)

		fileSegment.ContentUUID = newContentUUID
		curUUID = fileSegment.NextUUID
		nextSegmentUUID := uuid.New()
		if head {
			fileHeader.HeadUUID = curSegmentUUID
			head = false
		}
		thisSegmentUUID := curSegmentUUID
		if curUUID != uuid.Nil {
			fileSegment.NextUUID = nextSegmentUUID
			curSegmentUUID = nextSegmentUUID
		}

		// Store File Segment
		// Marshalling and encrypting FileSegment struct
		var plainFileSegment []byte
		plainFileSegment, err = json.Marshal(fileSegment)
		if err != nil {
			return err
		}
		var encryptedFileSegment []byte
		encryptedFileSegment, err = EncMacHelper(newSymKey, newHMACKey, plainFileSegment)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(thisSegmentUUID, encryptedFileSegment)
	}
	fileHeader.TailUUID = curSegmentUUID

	// Store File Header
	// Marshalling and encrypting FileHeader struct
	var plainFileHeader []byte
	plainFileHeader, err = json.Marshal(fileHeader)
	if err != nil {
		return err
	}
	var encryptedFileHeader []byte
	encryptedFileHeader, err = EncMacHelper(newSymKey, newHMACKey, plainFileHeader)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newFileHeaderUUID, encryptedFileHeader)

	return nil
}

func ReKeyAll(nodeKey NodeKey, newSymKey []byte, newHMACKey []byte, newFileHeaderUUID uuid.UUID) (err error) {
	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(nodeKey.FileNodeID)
	if (!ok) {
		return errors.New("File Node was deleted or unauthorized access")
	}
	var decNode []byte
	decNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return err
	}

	fileNode.SymKey = newSymKey
	fileNode.HMACKey = newHMACKey
	fileNode.FileHeaderUUID = newFileHeaderUUID

	// Loop through all further shared nodes
    for _, childNodeKey := range fileNode.UsernameToFileNode {
        err = ReKeyAll(childNodeKey, newSymKey, newHMACKey, newFileHeaderUUID)
		if err != nil {
			return err
		}
    }

	// Marshalling and encrypting FileNode struct
	var plainFileNode []byte
	plainFileNode, err = json.Marshal(fileNode)
	if err != nil {
		return err
	}
	var encryptedFileNode []byte
	encryptedFileNode, err = EncMacHelper(decNode[:16], hmacNode[:16], plainFileNode)
	if err != nil {
		return err
	}

	// Storing FileNode struct in the Datastore
	userlib.DatastoreSet(nodeKey.FileNodeID, encryptedFileNode)

	return nil
}

func DeleteAll(nodeKey NodeKey) (err error) {
	// Decrypting and Unmarshalling the FileNode struct
	finalNodeText, ok := userlib.DatastoreGet(nodeKey.FileNodeID)
	if (!ok) {
		return errors.New("File Node was deleted or unauthorized access")
	}
	var decNode []byte
	decNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("encUser"))
	if err != nil {
		return err
	}
	var hmacNode []byte
	hmacNode, err = userlib.HashKDF(nodeKey.SourceKey, []byte("hmac"))
	if err != nil {
		return err
	}
	var plainNodeText []byte
	plainNodeText, err = MacDecHelper(decNode[:16], hmacNode[:16], finalNodeText)
	if err != nil {
		return err
	}
	var fileNode FileNode
	fileNodePtr := &fileNode
	err = json.Unmarshal(plainNodeText, fileNodePtr)
	if err != nil {
		return err
	}

	// Loop through all further shared nodes
    for _, childNodeKey := range fileNode.UsernameToFileNode {
        err = DeleteAll(childNodeKey)
		if err != nil {
			return err
		}
    }

	userlib.DatastoreDelete(nodeKey.FileNodeID)
	return nil
}
